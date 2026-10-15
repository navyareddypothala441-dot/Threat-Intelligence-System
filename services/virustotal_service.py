import os
import base64
import requests
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

BASE_URL = "https://www.virustotal.com/api/v3"


def _headers():
    if not VIRUSTOTAL_API_KEY:
        raise RuntimeError(
            "VIRUSTOTAL_API_KEY is missing in .env"
        )

    return {
        "x-apikey": VIRUSTOTAL_API_KEY
    }


def _get(endpoint):
    url = f"{BASE_URL}/{endpoint}"

    response = requests.get(
        url,
        headers=_headers(),
        timeout=20
    )

    if response.status_code == 404:
        return {
            "error": "Indicator not found in VirusTotal",
            "status_code": 404
        }

    response.raise_for_status()

    return response.json()


# =========================================================
# IP
# =========================================================

def get_ip_report(ip):
    return _get(
        f"ip_addresses/{ip}"
    )


def parse_ip_report(data):
    if not isinstance(data, dict):
        return {}

    if "error" in data:
        return data

    attrs = (
        data.get("data", {})
        .get("attributes", {})
    )

    stats = attrs.get(
        "last_analysis_stats",
        {}
    )

    return {
        "malicious": stats.get(
            "malicious",
            0
        ),
        "suspicious": stats.get(
            "suspicious",
            0
        ),
        "harmless": stats.get(
            "harmless",
            0
        ),
        "undetected": stats.get(
            "undetected",
            0
        ),

        "country": attrs.get(
            "country"
        ),

        "asn": attrs.get(
            "asn"
        ),

        "organization": attrs.get(
            "as_owner"
        ),

        "reputation": attrs.get(
            "reputation",
            0
        ),

        "tags": attrs.get(
            "tags",
            []
        ),

        "network": attrs.get(
            "network"
        ),

        "analysis_status": "Available"
    }


# =========================================================
# GENERIC INDICATOR
# =========================================================

def get_indicator_report(ioc):
    ioc = ioc.strip()

    # URL
    if ioc.startswith(
        ("http://", "https://")
    ):
        url_id = base64.urlsafe_b64encode(
            ioc.encode()
        ).decode().strip("=")

        return _get(
            f"urls/{url_id}"
        )

    # HASH
    hash_length = len(ioc)

    if hash_length in [
        32,
        40,
        64
    ]:
        return _get(
            f"files/{ioc}"
        )

    # DOMAIN
    return _get(
        f"domains/{ioc}"
    )


def parse_indicator_report(data):
    if not isinstance(data, dict):
        return {}

    if "error" in data:
        return data

    attrs = (
        data.get("data", {})
        .get("attributes", {})
    )

    stats = attrs.get(
        "last_analysis_stats",
        {}
    )

    result = {
        "malicious": stats.get(
            "malicious",
            0
        ),

        "suspicious": stats.get(
            "suspicious",
            0
        ),

        "harmless": stats.get(
            "harmless",
            0
        ),

        "undetected": stats.get(
            "undetected",
            0
        ),

        "reputation": attrs.get(
            "reputation",
            0
        ),

        "tags": attrs.get(
            "tags",
            []
        ),

        "categories": attrs.get(
            "categories",
            {}
        ),

        "country": attrs.get(
            "country"
        ),

        "asn": attrs.get(
            "asn"
        ),

        "organization": attrs.get(
            "as_owner"
        ),

        "analysis_status": "Available"
    }

    # FILE INFORMATION
    result.update({
        "file_name": attrs.get(
            "meaningful_name"
        ),

        "file_type": attrs.get(
            "type_description"
        ),

        "size": attrs.get(
            "size"
        ),

        "md5": attrs.get(
            "md5"
        ),

        "sha1": attrs.get(
            "sha1"
        ),

        "sha256": attrs.get(
            "sha256"
        ),

        "first_submission_date":
            attrs.get(
                "first_submission_date"
            ),

        "last_submission_date":
            attrs.get(
                "last_submission_date"
            ),

        "times_submitted":
            attrs.get(
                "times_submitted"
            ),

        "popular_threat_classification":
            attrs.get(
                "popular_threat_classification",
                {}
            )
    })

    # URL
    result["url"] = attrs.get(
        "url"
    )

    # DOMAIN
    result["last_dns_records"] = (
        attrs.get(
            "last_dns_records",
            []
        )
    )

    return result