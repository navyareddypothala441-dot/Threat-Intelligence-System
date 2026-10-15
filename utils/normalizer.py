
def normalize_ip_data(
    vt_data=None,
    abuse_data=None,
    geolocation_data=None
):

    vt_data = vt_data or {}
    abuse_data = abuse_data or {}
    geolocation_data = geolocation_data or {}

    normalized = {

        "ioc": (
            vt_data.get("ip")
            or abuse_data.get("ip")
            or geolocation_data.get("ip")
        ),

        "ioc_type": "IP Address",

        # ----------------------------------------------------
        # Geographic information
        # ----------------------------------------------------

        "country": (
            geolocation_data.get("country")
            or vt_data.get("country")
            or abuse_data.get("country")
        ),

        "region": geolocation_data.get(
            "region"
        ),

        "city": geolocation_data.get(
            "city"
        ),

        "latitude": geolocation_data.get(
            "latitude"
        ),

        "longitude": geolocation_data.get(
            "longitude"
        ),

        # ----------------------------------------------------
        # Network information
        # ----------------------------------------------------

        "isp": (
            geolocation_data.get("isp")
            or abuse_data.get("isp")
        ),

        "organization": (
            geolocation_data.get("organization")
            or vt_data.get("organization")
            or abuse_data.get("isp")
        ),

        "asn": (
            geolocation_data.get("asn")
            or vt_data.get("asn")
        ),

        # ----------------------------------------------------
        # VirusTotal
        # ----------------------------------------------------

        "reputation": vt_data.get(
            "reputation"
        ),

        "malicious": vt_data.get(
            "malicious",
            0
        ),

        "suspicious": vt_data.get(
            "suspicious",
            0
        ),

        "harmless": vt_data.get(
            "harmless",
            0
        ),

        "undetected": vt_data.get(
            "undetected",
            0
        ),

        "tags": vt_data.get(
            "tags",
            []
        ),

        "domains": vt_data.get(
            "domains",
            []
        ),

        "urls": vt_data.get(
            "urls",
            []
        ),

        "hostnames": vt_data.get(
            "hostnames",
            []
        ),

        # ----------------------------------------------------
        # AbuseIPDB
        # ----------------------------------------------------

        "abuse_confidence_score": abuse_data.get(
            "abuse_confidence_score",
            0
        ),

        "total_reports": abuse_data.get(
            "total_reports",
            0
        ),

        "domain": abuse_data.get(
            "domain"
        ),

        "usage_type": abuse_data.get(
            "usage_type"
        ),

        "is_public": abuse_data.get(
            "is_public"
        ),

        "is_whitelisted": abuse_data.get(
            "is_whitelisted"
        ),

        "last_reported_at": abuse_data.get(
            "last_reported_at"
        ),

        "sources": []
    }

    if (
        vt_data
        and "error" not in vt_data
    ):

        normalized["sources"].append(
            "VirusTotal"
        )

    if (
        abuse_data
        and "error" not in abuse_data
    ):

        normalized["sources"].append(
            "AbuseIPDB"
        )

    if (
        geolocation_data
        and "error" not in geolocation_data
    ):

        normalized["sources"].append(
            "Geolocation"
        )

    return normalized


# ============================================================
# DOMAIN
# ============================================================

def normalize_domain_data(
    whois_data=None,
    vt_data=None
):

    whois_data = whois_data or {}
    vt_data = vt_data or {}

    return {

        "ioc": (
            whois_data.get("domain")
            or vt_data.get("domain")
        ),

        "ioc_type": "Domain",

        "registrar": (
            whois_data.get("registrar")
            or vt_data.get("registrar")
        ),

        "creation_date": (
            whois_data.get("creation_date")
            or vt_data.get("creation_date")
        ),

        "expiration_date": (
            whois_data.get("expiration_date")
            or vt_data.get("expiration_date")
        ),

        "name_servers": (
            whois_data.get("name_servers")
            or vt_data.get("name_servers", [])
        ),

        "status": (
            whois_data.get("status")
            or vt_data.get("status", [])
        ),

        "reputation": vt_data.get(
            "reputation",
            0
        ),

        "malicious": vt_data.get(
            "malicious",
            0
        ),

        "suspicious": vt_data.get(
            "suspicious",
            0
        ),

        "harmless": vt_data.get(
            "harmless",
            0
        ),

        "undetected": vt_data.get(
            "undetected",
            0
        ),

        "tags": vt_data.get(
            "tags",
            []
        ),

        "categories": vt_data.get(
            "categories",
            {}
        ),

        "sources": [
            source
            for source, data in [
                ("WHOIS", whois_data),
                ("VirusTotal", vt_data)
            ]
            if data
            and "error" not in data
        ]
    }


# ============================================================
# URL
# ============================================================

def normalize_url_data(
    vt_data=None
):

    vt_data = vt_data or {}

    return {

        "ioc": vt_data.get(
            "url"
        ),

        "ioc_type": "URL",

        "url_id": vt_data.get(
            "url_id"
        ),

        "reputation": vt_data.get(
            "reputation",
            0
        ),

        "malicious": vt_data.get(
            "malicious",
            0
        ),

        "suspicious": vt_data.get(
            "suspicious",
            0
        ),

        "harmless": vt_data.get(
            "harmless",
            0
        ),

        "undetected": vt_data.get(
            "undetected",
            0
        ),

        "tags": vt_data.get(
            "tags",
            []
        ),

        "final_url": vt_data.get(
            "final_url"
        ),

        "title": vt_data.get(
            "title"
        ),

        "http_response_code": vt_data.get(
            "http_response_code"
        ),

        "categories": vt_data.get(
            "categories",
            {}
        ),

        "sources": [
            "VirusTotal"
        ]
        if vt_data
        and "error" not in vt_data
        else []
    }


# ============================================================
# FILE HASH
# ============================================================

def normalize_hash_data(
    vt_data=None
):

    vt_data = vt_data or {}

    return {

        "ioc": vt_data.get(
            "hash"
        ),

        "ioc_type": "File Hash",

        "hash": vt_data.get(
            "hash"
        ),

        "md5": vt_data.get(
            "md5"
        ),

        "sha1": vt_data.get(
            "sha1"
        ),

        "sha256": vt_data.get(
            "sha256"
        ),

        "size": vt_data.get(
            "size"
        ),

        "type_description": vt_data.get(
            "type_description"
        ),

        "type_tag": vt_data.get(
            "type_tag"
        ),

        "reputation": vt_data.get(
            "reputation",
            0
        ),

        "malicious": vt_data.get(
            "malicious",
            0
        ),

        "suspicious": vt_data.get(
            "suspicious",
            0
        ),

        "harmless": vt_data.get(
            "harmless",
            0
        ),

        "undetected": vt_data.get(
            "undetected",
            0
        ),

        "tags": vt_data.get(
            "tags",
            []
        ),

        "names": vt_data.get(
            "names",
            []
        ),

        "sources": [
            "VirusTotal"
        ]
        if vt_data
        and "error" not in vt_data
        else []
    }