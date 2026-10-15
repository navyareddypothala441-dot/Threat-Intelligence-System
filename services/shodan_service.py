import os
import requests
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv(
    "SHODAN_API_KEY"
)

BASE_URL = (
    "https://api.shodan.io/shodan/host"
)


def get_ip_report(ip):
    if not SHODAN_API_KEY:
        return {
            "error": (
                "SHODAN_API_KEY "
                "is missing in .env"
            )
        }

    url = (
        f"{BASE_URL}/{ip}"
        f"?key={SHODAN_API_KEY}"
    )

    try:
        response = requests.get(
            url,
            timeout=20
        )

        if response.status_code == 404:
            return {
                "error": (
                    "IP not found "
                    "in Shodan"
                )
            }

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

    vulnerabilities = []

    vulns = data.get(
        "vulns",
        []
    )

    if isinstance(vulns, dict):
        vulnerabilities = list(
            vulns.keys()
        )

    elif isinstance(vulns, list):
        vulnerabilities = vulns

    services = []

    for item in data.get(
        "data",
        []
    ):
        if not isinstance(
            item,
            dict
        ):
            continue

        services.append({
            "port": item.get(
                "port"
            ),

            "transport": item.get(
                "transport"
            ),

            "product": item.get(
                "product"
            ),

            "version": item.get(
                "version"
            )
        })

    return {
        "ip": data.get(
            "ip_str"
        ),

        "organization": data.get(
            "org"
        ),

        "isp": data.get(
            "isp"
        ),

        "asn": data.get(
            "asn"
        ),

        "country": data.get(
            "country_name"
        ),

        "city": data.get(
            "city"
        ),

        "latitude": data.get(
            "latitude"
        ),

        "longitude": data.get(
            "longitude"
        ),

        "ports": data.get(
            "ports",
            []
        ),

        "hostnames": data.get(
            "hostnames",
            []
        ),

        "domains": data.get(
            "domains",
            []
        ),

        "vulnerabilities":
            vulnerabilities,

        "services": services
    }