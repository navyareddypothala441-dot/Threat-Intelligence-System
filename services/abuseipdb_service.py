import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv(
    "ABUSEIPDB_API_KEY"
)

BASE_URL = (
    "https://api.abuseipdb.com/api/v2/check"
)


def get_ip_report(ip):
    if not ABUSEIPDB_API_KEY:
        return {
            "error": (
                "ABUSEIPDB_API_KEY "
                "is missing in .env"
            )
        }

    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        response = requests.get(
            BASE_URL,
            headers=headers,
            params=params,
            timeout=20
        )

        response.raise_for_status()

        return response.json()

    except Exception as e:
        return {
            "error": str(e)
        }


def parse_ip_report(data):
    if not isinstance(data, dict):
        return {}

    if "error" in data:
        return data

    info = data.get(
        "data",
        {}
    )

    return {
        "ip_address": info.get(
            "ipAddress"
        ),

        "is_public": info.get(
            "isPublic"
        ),

        "ip_version": info.get(
            "ipVersion"
        ),

        "is_whitelisted": info.get(
            "isWhitelisted"
        ),

        "abuse_confidence_score":
            info.get(
                "abuseConfidenceScore",
                0
            ),

        "country_code": info.get(
            "countryCode"
        ),

        "usage_type": info.get(
            "usageType"
        ),

        "isp": info.get(
            "isp"
        ),

        "domain": info.get(
            "domain"
        ),

        "hostnames": info.get(
            "hostnames",
            []
        ),

        "total_reports": info.get(
            "totalReports",
            0
        ),

        "num_distinct_users":
            info.get(
                "numDistinctUsers",
                0
            ),

        "last_reported_at":
            info.get(
                "lastReportedAt"
            )
    }