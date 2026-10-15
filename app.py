from routes.watchlist import watchlist_bp

import os
from datetime import timedelta

from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for,
)

from routes.alerts import alerts_bp

from routes.reports import reports_bp
from routes.auth import auth_bp
from routes.admin import admin_bp

# =========================================================

# MACHINE LEARNING

# =========================================================



from ml.predict import predict_risk





# =========================================================

# VIRUSTOTAL

# =========================================================



from services.virustotal_service import (

    get_ip_report as get_vt_ip_report,

    parse_ip_report as parse_vt_ip_report,

    get_indicator_report as get_vt_indicator_report,

    parse_indicator_report as parse_vt_indicator_report,

)





# =========================================================

# ABUSEIPDB

# =========================================================



from services.abuseipdb_service import (

    get_ip_report as get_abuseipdb_report,

    parse_ip_report as parse_abuseipdb_report,

)





# =========================================================

# SHODAN

# =========================================================



from services.shodan_service import (

    get_ip_report as get_shodan_ip_report,

    parse_ip_report as parse_shodan_ip_report,

)





# =========================================================

# WHOIS

# =========================================================



from services.whois_service import get_domain_whois





# =========================================================

# GEOLOCATION

# =========================================================



from services.geolocation_service import get_ip_geolocation





# =========================================================

# NETWORK ENRICHMENT

# =========================================================



from services.network_enrichment_service import (

    get_domain_enrichment,

    get_url_enrichment,

)





# =========================================================

# CORRELATION

# =========================================================



from services.correlation_service import (

    get_related_iocs,

    create_relationships_from_vt,

    create_relationships_from_shodan,

    get_relationship_count,

)





# =========================================================

# RISK

# =========================================================



from services.risk_service import calculate_risk_score





# =========================================================

# IOC DETECTION

# =========================================================



from utils.ioc_detector import detect_ioc





# =========================================================

# NORMALIZATION

# =========================================================



from utils.normalizer import (

    normalize_ip_data,

    normalize_domain_data,

    normalize_url_data,

    normalize_hash_data,

)





# =========================================================

# DATABASE

# =========================================================



from database.db import get_connection





# =========================================================

# DASHBOARD

# =========================================================



from routes.dashboard import dashboard_bp





from routes.threat_graph import threat_graph_bp





# =========================================================

# FLASK APPLICATION

# =========================================================



app = Flask(__name__)

# =========================================================
# SESSION / SECURITY CONFIGURATION
# =========================================================

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "osint-development-secret-change-this"
)

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=60)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Keep False for local development over HTTP.
# Set True after deployment behind HTTPS.
app.config["SESSION_COOKIE_SECURE"] = False


# =========================================================
# BLUEPRINTS
# =========================================================

app.register_blueprint(dashboard_bp)
app.register_blueprint(threat_graph_bp)
app.register_blueprint(watchlist_bp)
app.register_blueprint(alerts_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)

# =========================================================
# LOGIN PROTECTION
# =========================================================

@app.before_request
def require_login():
    public_endpoints = {
        "auth.login",
        "auth.register",
        "static",
    }

    endpoint = request.endpoint

    if endpoint is None:
        return None

    if endpoint in public_endpoints:
        return None

    if not session.get("user_id"):
        return redirect(url_for("auth.login"))

    return None


# =========================================================

# HELPER FUNCTIONS

# =========================================================



def safe_float(value):

    try:

        if value in [None, "", "Unknown", "N/A"]:

            return None



        return float(value)



    except (ValueError, TypeError):

        return None





def safe_int(value, default=0):

    try:

        if value in [None, "", "Unknown", "N/A"]:

            return default



        # Handle ASN values like AS15169

        if isinstance(value, str):

            value = value.strip()



            if value.upper().startswith("AS"):

                value = value[2:]



        return int(value)



    except (ValueError, TypeError):

        return default





def ensure_dict(value):

    if isinstance(value, dict):

        return value



    return {}





def ensure_list(value):

    if isinstance(value, list):

        return value



    if value is None:

        return []



    return [value]





# =========================================================

# SAVE INVESTIGATION

# =========================================================



def save_investigation(
    ioc,
    ioc_type,
    normalized,
    risk_score,
    risk_level,
    ml_prediction=None,
    ml_confidence=None,
):

    connection = None
    cursor = None

    try:

        normalized = ensure_dict(normalized)

        latitude = safe_float(
            normalized.get("latitude")
        )

        longitude = safe_float(
            normalized.get("longitude")
        )

        asn = safe_int(
            normalized.get("asn"),
            None
        )

        risk_score_db = safe_int(
            risk_score,
            0
        )

        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO investigations
            (
                ioc,
                ioc_type,
                country,
                region,
                city,
                latitude,
                longitude,
                isp,
                organization,
                asn,
                risk_score,
                risk_level,
                ml_prediction,
                ml_confidence
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
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )

            RETURNING id
            """,

            (
                ioc,
                ioc_type,
                normalized.get("country"),
                normalized.get("region"),
                normalized.get("city"),
                latitude,
                longitude,
                normalized.get("isp"),
                normalized.get("organization"),
                asn,
                risk_score_db,
                risk_level,
                ml_prediction,
                ml_confidence,
            ),
        )

        row = cursor.fetchone()
        investigation_id = row[0] if row else None

        connection.commit()

        print(
            "Investigation saved successfully. ID:",
            investigation_id
        )

        return investigation_id

    except Exception as e:

        print("Database save error:", e)

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





# =========================================================

# VIRUSTOTAL INDICATOR HELPER

# =========================================================



def query_virustotal_indicator(ioc):



    try:



        raw = get_vt_indicator_report(ioc)



        data = parse_vt_indicator_report(raw)



        return ensure_dict(data)



    except Exception as e:



        print("VirusTotal indicator error:", e)



        return {

            "error": str(e)

        }





# =========================================================

# RUN MACHINE LEARNING

# =========================================================



def run_ml(

    vt_data,

    abuse_data=None,

    relationship_count=0,

    successful_sources=1,

    normalized=None,

    recent_activity=False,

):



    abuse_data = ensure_dict(abuse_data)

    normalized = ensure_dict(normalized)



    try:



        result = predict_risk(



            malicious_count=safe_int(

                vt_data.get("malicious"),

                0

            ),



            suspicious_count=safe_int(

                vt_data.get("suspicious"),

                0

            ),



            abuse_confidence_score=safe_int(

                abuse_data.get(

                    "abuse_confidence_score"

                ),

                0

            ),



            total_reports=safe_int(

                abuse_data.get(

                    "total_reports"

                ),

                0

            ),



            related_ioc_count=relationship_count,



            source_count=successful_sources,



            port_count=len(

                ensure_list(

                    normalized.get("ports")

                )

            ),



            vulnerability_count=len(

                ensure_list(

                    normalized.get(

                        "vulnerabilities"

                    )

                )

            ),



            recent_activity=recent_activity,



            reputation=safe_int(

                vt_data.get("reputation"),

                0

            ),

        )



        print("ML Result:", result)



        return result



    except Exception as e:



        print("ML prediction error:", e)



        return {

            "available": False,

            "error": str(e)

        }





# =========================================================

# RISK HELPER

# =========================================================



def build_risk(

    vt_data,

    abuse_data=None,

    relationship_count=0,

    multiple_sources=False,

    recent_activity=False,

):



    abuse_data = ensure_dict(abuse_data)



    try:



        result = calculate_risk_score(



            vt_data=vt_data,



            abuse_data=abuse_data,



            related_ioc_count=relationship_count,



            multiple_sources=multiple_sources,



            recent_activity=recent_activity,

        )



    except Exception as e:



        print("Risk calculation error:", e)



        result = {

            "score": 0,

            "level": "LOW",

            "reasons": [

                "Risk calculation could not be completed."

            ]

        }



    result = ensure_dict(result)



    return (

        safe_int(

            result.get("score"),

            0

        ),

        result.get(

            "level",

            "LOW"

        ),

        ensure_list(

            result.get(

                "reasons"

            )

        ),

    )





# =========================================================

# HOME

# =========================================================



@app.route("/")

def home():



    return render_template(

        "index.html"

    )





# =========================================================

# INVESTIGATE

# =========================================================



@app.route(

    "/investigate",

    methods=["POST"]

)

def investigate():



    ioc = request.form.get(

        "ioc",

        ""

    ).strip()



    if not ioc:



        return render_template(



            "result.html",



            ioc="",



            ioc_type="Unknown",



            normalized={},



            vt_data=None,



            risk_score=0,



            risk_level="LOW",



            risk_reasons=[

                "No IOC was provided."

            ],



            relationships=[],



            relationships_created=0,



            ml_result=None,



            investigation_id=None,

        )



    ioc_type = detect_ioc(ioc)



    print()

    print("=" * 60)

    print("Investigating IOC:", ioc)

    print("IOC Type:", ioc_type)

    print("=" * 60)





    # =====================================================

    # IP ADDRESS

    # =====================================================



    if ioc_type == "IP Address":



        # VIRUSTOTAL



        print(

            "\n[1] Querying VirusTotal..."

        )



        try:



            vt_raw = get_vt_ip_report(

                ioc

            )



            vt_data = parse_vt_ip_report(

                vt_raw

            )



        except Exception as e:



            print(

                "VirusTotal error:",

                e

            )



            vt_data = {

                "error": str(e)

            }



        vt_data = ensure_dict(

            vt_data

        )



        print(

            "VirusTotal:",

            vt_data

        )





        # ABUSEIPDB



        print(

            "\n[2] Querying AbuseIPDB..."

        )



        try:



            abuse_raw = (

                get_abuseipdb_report(

                    ioc

                )

            )



            abuse_data = (

                parse_abuseipdb_report(

                    abuse_raw

                )

            )



        except Exception as e:



            print(

                "AbuseIPDB error:",

                e

            )



            abuse_data = {

                "error": str(e)

            }



        abuse_data = ensure_dict(

            abuse_data

        )



        print(

            "AbuseIPDB:",

            abuse_data

        )





        # SHODAN



        print(

            "\n[3] Querying Shodan..."

        )



        try:



            shodan_raw = (

                get_shodan_ip_report(

                    ioc

                )

            )



            shodan_data = (

                parse_shodan_ip_report(

                    shodan_raw

                )

            )



        except Exception as e:



            print(

                "Shodan error:",

                e

            )



            shodan_data = {

                "error": str(e)

            }



        shodan_data = ensure_dict(

            shodan_data

        )



        print(

            "Shodan:",

            shodan_data

        )





        # GEOLOCATION



        print(

            "\n[4] Querying Geolocation..."

        )



        try:



            geolocation_data = (

                get_ip_geolocation(

                    ioc

                )

            )



        except Exception as e:



            print(

                "Geolocation error:",

                e

            )



            geolocation_data = {

                "error": str(e)

            }



        geolocation_data = ensure_dict(

            geolocation_data

        )



        print(

            "Geolocation:",

            geolocation_data

        )





        # NORMALIZATION



        print(

            "\n[5] Normalizing..."

        )



        try:



            normalized = normalize_ip_data(



                vt_data=vt_data,



                abuse_data=abuse_data,



                geolocation_data=(

                    geolocation_data

                ),

            )



        except Exception as e:



            print(

                "Normalization error:",

                e

            )



            normalized = {}



        normalized = ensure_dict(

            normalized

        )



        normalized["ioc"] = ioc

        normalized["ioc_type"] = ioc_type



        # fallback information



        if (

            not normalized.get("country")

            and vt_data.get("country")

        ):

            normalized["country"] = (

                vt_data.get("country")

            )



        if (

            not normalized.get(

                "organization"

            )

            and vt_data.get(

                "organization"

            )

        ):

            normalized["organization"] = (

                vt_data.get(

                    "organization"

                )

            )



        if (

            not normalized.get("asn")

            and vt_data.get("asn")

        ):

            normalized["asn"] = (

                vt_data.get("asn")

            )



        normalized["shodan"] = (

            shodan_data

        )



        normalized["ports"] = (

            ensure_list(

                shodan_data.get(

                    "ports"

                )

            )

        )



        normalized[

            "vulnerabilities"

        ] = ensure_list(

            shodan_data.get(

                "vulnerabilities"

            )

        )



        if (

            geolocation_data

            and "error"

            not in geolocation_data

        ):

            normalized[

                "geolocation_source"

            ] = (

                "IP Geolocation Service"

            )





        # RELATIONSHIPS



        print(

            "\n[6] Creating relationships..."

        )



        relationships_created = 0



        try:



            count = (

                create_relationships_from_vt(

                    ioc,

                    vt_data

                )

            )



            if isinstance(

                count,

                int

            ):

                relationships_created += count



        except Exception as e:



            print(

                "VT relationship error:",

                e

            )



        try:



            count = (

                create_relationships_from_shodan(

                    ioc,

                    shodan_data

                )

            )



            if isinstance(

                count,

                int

            ):

                relationships_created += count



        except Exception as e:



            print(

                "Shodan relationship error:",

                e

            )



        relationships = ensure_list(

            get_related_iocs(ioc)

        )



        relationship_count = (

            get_relationship_count(

                ioc

            )

        )



        print(

            "Total relationships:",

            relationship_count

        )





        # SOURCES



        successful_sources = 0



        for source in [

            vt_data,

            abuse_data,

            shodan_data,

            geolocation_data,

        ]:



            if (

                isinstance(source, dict)

                and source

                and "error" not in source

            ):

                successful_sources += 1



        multiple_sources = (

            successful_sources >= 2

        )



        recent_activity = bool(

            abuse_data.get(

                "last_reported_at"

            )

        )





        # RISK



        risk_score, risk_level, risk_reasons = (

            build_risk(



                vt_data,



                abuse_data,



                relationship_count,



                multiple_sources,



                recent_activity,

            )

        )





        # MACHINE LEARNING



        ml_result = run_ml(



            vt_data,



            abuse_data,



            relationship_count,



            successful_sources,



            normalized,



            recent_activity,

        )





    # =====================================================

    # DOMAIN

    # =====================================================



    elif ioc_type == "Domain":



        print(

            "\n[1] Querying VirusTotal..."

        )



        vt_data = (

            query_virustotal_indicator(

                ioc

            )

        )



        print(

            "VirusTotal:",

            vt_data

        )





        # WHOIS



        print(

            "\n[2] Querying WHOIS..."

        )



        try:



            whois_data = (

                get_domain_whois(

                    ioc

                )

            )



        except Exception as e:



            print(

                "WHOIS error:",

                e

            )



            whois_data = {

                "error": str(e)

            }



        whois_data = ensure_dict(

            whois_data

        )



        print(

            "WHOIS:",

            whois_data

        )





        # NORMALIZATION



        print(

            "\n[3] Normalizing domain..."

        )



        try:



            normalized = (

                normalize_domain_data(



                    whois_data=whois_data,



                    vt_data=vt_data,

                )

            )



        except Exception as e:



            print(

                "Domain normalization error:",

                e

            )



            normalized = {}



        normalized = ensure_dict(

            normalized

        )



        normalized["ioc"] = ioc

        normalized["ioc_type"] = ioc_type





        # DOMAIN -> IP -> GEOLOCATION



        print(

            "\n[4] Resolving domain..."

        )



        try:



            domain_enrichment = (

                get_domain_enrichment(

                    ioc

                )

            )



        except Exception as e:



            print(

                "Domain enrichment error:",

                e

            )



            domain_enrichment = {

                "resolved_ips": [],

                "locations": []

            }



        domain_enrichment = (

            ensure_dict(

                domain_enrichment

            )

        )



        resolved_ips = ensure_list(

            domain_enrichment.get(

                "resolved_ips"

            )

        )



        locations = ensure_list(

            domain_enrichment.get(

                "locations"

            )

        )



        normalized[

            "resolved_ips"

        ] = resolved_ips



        normalized[

            "resolved_locations"

        ] = locations



        print(

            "Resolved IPs:",

            resolved_ips

        )



        print(

            "Resolved Locations:",

            locations

        )



        if locations:



            primary = locations[0]



            normalized["country"] = (

                primary.get(

                    "country"

                )

            )



            normalized["region"] = (

                primary.get(

                    "region"

                )

            )



            normalized["city"] = (

                primary.get(

                    "city"

                )

            )



            normalized["latitude"] = (

                primary.get(

                    "latitude"

                )

            )



            normalized["longitude"] = (

                primary.get(

                    "longitude"

                )

            )



            normalized["isp"] = (

                primary.get(

                    "isp"

                )

            )



            normalized[

                "organization"

            ] = primary.get(

                "organization"

            )



            normalized["asn"] = (

                primary.get(

                    "asn"

                )

            )



            normalized[

                "geolocation_source"

            ] = (

                "Resolved Domain IP"

            )





        # CORRELATION



        print(

            "\n[5] Creating relationships..."

        )



        try:



            create_relationships_from_vt(

                ioc,

                vt_data

            )



        except Exception as e:



            print(

                "Domain VT relationship error:",

                e

            )



        relationships = ensure_list(

            get_related_iocs(ioc)

        )



        relationship_count = (

            get_relationship_count(

                ioc

            )

        )



        print(

            "Domain relationships:",

            relationship_count

        )





        successful_sources = 0



        for source in [

            vt_data,

            whois_data,

            domain_enrichment,

        ]:



            if (

                isinstance(source, dict)

                and source

                and "error" not in source

            ):

                successful_sources += 1



        risk_score, risk_level, risk_reasons = (

            build_risk(



                vt_data=vt_data,



                relationship_count=(

                    relationship_count

                ),



                multiple_sources=(

                    successful_sources >= 2

                ),

            )

        )



        ml_result = run_ml(



            vt_data=vt_data,



            relationship_count=(

                relationship_count

            ),



            successful_sources=(

                successful_sources

            ),



            normalized=normalized,

        )





    # =====================================================

    # URL

    # =====================================================



    elif ioc_type == "URL":



        print(

            "\n[1] Querying VirusTotal..."

        )



        vt_data = (

            query_virustotal_indicator(

                ioc

            )

        )



        print(

            "VirusTotal:",

            vt_data

        )





        # NORMALIZE



        print(

            "\n[2] Normalizing URL..."

        )



        try:



            normalized = (

                normalize_url_data(

                    vt_data=vt_data

                )

            )



        except TypeError:



            # Some versions of the

            # normalizer use positional input.

            normalized = (

                normalize_url_data(

                    vt_data

                )

            )



        except Exception as e:



            print(

                "URL normalization error:",

                e

            )



            normalized = {}



        normalized = ensure_dict(

            normalized

        )



        normalized["ioc"] = ioc

        normalized["ioc_type"] = ioc_type





        # URL -> DOMAIN -> IP -> GEO



        print(

            "\n[3] Resolving URL host..."

        )



        try:



            url_enrichment = (

                get_url_enrichment(

                    ioc

                )

            )



        except Exception as e:



            print(

                "URL enrichment error:",

                e

            )



            url_enrichment = {

                "domain": None,

                "resolved_ips": [],

                "locations": []

            }



        url_enrichment = (

            ensure_dict(

                url_enrichment

            )

        )



        domain = url_enrichment.get(

            "domain"

        )



        resolved_ips = ensure_list(

            url_enrichment.get(

                "resolved_ips"

            )

        )



        locations = ensure_list(

            url_enrichment.get(

                "locations"

            )

        )



        normalized["domain"] = domain



        normalized[

            "resolved_ips"

        ] = resolved_ips



        normalized[

            "resolved_locations"

        ] = locations



        print(

            "URL Domain:",

            domain

        )



        print(

            "Resolved IPs:",

            resolved_ips

        )



        print(

            "Resolved Locations:",

            locations

        )



        if locations:



            primary = locations[0]



            normalized["country"] = (

                primary.get(

                    "country"

                )

            )



            normalized["region"] = (

                primary.get(

                    "region"

                )

            )



            normalized["city"] = (

                primary.get(

                    "city"

                )

            )



            normalized["latitude"] = (

                primary.get(

                    "latitude"

                )

            )



            normalized["longitude"] = (

                primary.get(

                    "longitude"

                )

            )



            normalized["isp"] = (

                primary.get(

                    "isp"

                )

            )



            normalized[

                "organization"

            ] = primary.get(

                "organization"

            )



            normalized["asn"] = (

                primary.get(

                    "asn"

                )

            )



            normalized[

                "geolocation_source"

            ] = (

                "Resolved URL Domain IP"

            )





        # RELATED IOCS



        try:



            create_relationships_from_vt(

                ioc,

                vt_data

            )



        except Exception as e:



            print(

                "URL relationship error:",

                e

            )



        relationships = ensure_list(

            get_related_iocs(ioc)

        )



        relationship_count = (

            get_relationship_count(

                ioc

            )

        )



        successful_sources = 1



        if (

            domain

            and resolved_ips

        ):

            successful_sources += 1



        risk_score, risk_level, risk_reasons = (

            build_risk(



                vt_data=vt_data,



                relationship_count=(

                    relationship_count

                ),



                multiple_sources=False,

            )

        )



        ml_result = run_ml(



            vt_data=vt_data,



            relationship_count=(

                relationship_count

            ),



            successful_sources=(

                successful_sources

            ),



            normalized=normalized,

        )





    # =====================================================

    # HASH

    # =====================================================



    elif ioc_type in [

        "MD5 Hash",

        "SHA1 Hash",

        "SHA256 Hash",

    ]:



        print(

            "\n[1] Querying VirusTotal..."

        )



        vt_data = (

            query_virustotal_indicator(

                ioc

            )

        )



        print(

            "VirusTotal:",

            vt_data

        )





        # NORMALIZATION



        print(

            "\n[2] Normalizing hash..."

        )



        try:



            normalized = (

                normalize_hash_data(

                    vt_data=vt_data

                )

            )



        except TypeError:



            normalized = (

                normalize_hash_data(

                    vt_data

                )

            )



        except Exception as e:



            print(

                "Hash normalization error:",

                e

            )



            normalized = {}



        normalized = ensure_dict(

            normalized

        )



        normalized["ioc"] = ioc

        normalized["ioc_type"] = ioc_type





        # HASH DOES NOT HAVE DIRECT

        # PHYSICAL LOCATION



        normalized["country"] = (

            normalized.get("country")

        )



        normalized["region"] = (

            normalized.get("region")

        )



        normalized["city"] = (

            normalized.get("city")

        )



        normalized["latitude"] = (

            normalized.get("latitude")

        )



        normalized["longitude"] = (

            normalized.get("longitude")

        )



        normalized[

            "geolocation_source"

        ] = None





        # FILE INFORMATION



        normalized["file_name"] = (

            vt_data.get(

                "file_name"

            )

        )



        normalized["file_type"] = (

            vt_data.get(

                "file_type"

            )

        )



        normalized["size"] = (

            vt_data.get(

                "size"

            )

        )



        normalized["md5"] = (

            vt_data.get(

                "md5"

            )

        )



        normalized["sha1"] = (

            vt_data.get(

                "sha1"

            )

        )



        normalized["sha256"] = (

            vt_data.get(

                "sha256"

            )

        )



        normalized[

            "first_submission_date"

        ] = vt_data.get(

            "first_submission_date"

        )



        normalized[

            "last_submission_date"

        ] = vt_data.get(

            "last_submission_date"

        )



        normalized[

            "times_submitted"

        ] = vt_data.get(

            "times_submitted"

        )



        normalized[

            "popular_threat_classification"

        ] = vt_data.get(

            "popular_threat_classification",

            {}

        )



        normalized["tags"] = (

            ensure_list(

                vt_data.get(

                    "tags"

                )

            )

        )





        # RELATIONSHIPS



        try:



            create_relationships_from_vt(

                ioc,

                vt_data

            )



        except Exception as e:



            print(

                "Hash relationship error:",

                e

            )



        relationships = ensure_list(

            get_related_iocs(ioc)

        )



        relationship_count = (

            get_relationship_count(

                ioc

            )

        )



        risk_score, risk_level, risk_reasons = (

            build_risk(



                vt_data=vt_data,



                relationship_count=(

                    relationship_count

                ),



                multiple_sources=False,

            )

        )



        ml_result = run_ml(



            vt_data=vt_data,



            relationship_count=(

                relationship_count

            ),



            successful_sources=1,



            normalized=normalized,

        )





    # =====================================================

    # UNKNOWN

    # =====================================================



    else:



        return render_template(



            "result.html",



            ioc=ioc,



            ioc_type="Unknown",



            normalized={},



            vt_data=None,



            risk_score=0,



            risk_level="LOW",



            risk_reasons=[

                "Unsupported or invalid IOC."

            ],



            relationships=[],



            relationships_created=0,



            ml_result=None,



            investigation_id=None,

        )





    # =====================================================

    # SAVE RESULT

    # =====================================================



    print(

        "\nSaving investigation..."

    )



    ml_prediction = None
    ml_confidence = None

    if isinstance(ml_result, dict) and ml_result.get("available"):
        ml_prediction = (
            ml_result.get("prediction")
            or ml_result.get("risk")
        )
        ml_confidence = ml_result.get("confidence")

    investigation_id = save_investigation(
        ioc=ioc,
        ioc_type=ioc_type,
        normalized=normalized,
        risk_score=risk_score,
        risk_level=risk_level,
        ml_prediction=ml_prediction,
        ml_confidence=ml_confidence,
    )





    # =====================================================

    # DISPLAY RESULT

    # =====================================================



    return render_template(



        "result.html",



        ioc=ioc,



        ioc_type=ioc_type,



        normalized=normalized,



        vt_data=vt_data,



        risk_score=risk_score,



        risk_level=risk_level,



        risk_reasons=risk_reasons,



        relationships=relationships,



        relationships_created=(

            relationship_count

        ),



        ml_result=ml_result,



        investigation_id=investigation_id,

    )





# =========================================================

# HISTORY

# =========================================================



@app.route("/history")

@app.route("/history/")

def history():



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

                country,

                region,

                city,

                latitude,

                longitude,

                isp,

                organization,

                asn,

                risk_score,

                risk_level,

                created_at

            FROM investigations

            ORDER BY created_at DESC

            """

        )



        rows = cursor.fetchall()



        investigations = []



        for row in rows:



            investigations.append({



                "id": row[0],



                "ioc": row[1],



                "ioc_type": row[2],



                "country": row[3],



                "region": row[4],



                "city": row[5],



                "latitude": row[6],



                "longitude": row[7],



                "isp": row[8],



                "organization": row[9],



                "asn": row[10],



                "risk_score": row[11],



                "risk_level": row[12],



                "created_at": row[13],

            })



        return render_template(

            "history.html",

            investigations=investigations

        )



    except Exception as e:



        print(

            "History error:",

            e

        )



        return render_template(

            "history.html",

            investigations=[]

        )



    finally:



        if cursor:

            cursor.close()



        if connection:

            connection.close()





# =========================================================

# RUN

# =========================================================



if __name__ == "__main__":



    app.run(

        debug=True

    )