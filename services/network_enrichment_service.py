import socket
import ipaddress
from urllib.parse import urlparse

from services.geolocation_service import (
    get_ip_geolocation
)


def is_public_ip(ip):

    try:

        address = ipaddress.ip_address(
            ip
        )

        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_multicast
            and not address.is_reserved
            and not address.is_unspecified
        )

    except ValueError:

        return False


def resolve_domain_to_ips(domain):

    results = []

    try:

        addresses = socket.getaddrinfo(
            domain,
            None
        )

        for address in addresses:

            ip = address[4][0]

            if (
                ip not in results
                and is_public_ip(ip)
            ):
                results.append(ip)

    except Exception as e:

        print(
            "DNS resolution error:",
            e
        )

    return results


def geolocate_ips(ips):

    locations = []

    # Limit API calls.
    for ip in ips[:5]:

        try:

            geo = get_ip_geolocation(
                ip
            )

            if (
                isinstance(geo, dict)
                and geo
                and "error" not in geo
            ):

                locations.append({

                    "ip": ip,

                    "country": geo.get(
                        "country"
                    ),

                    "region": geo.get(
                        "region"
                    ),

                    "city": geo.get(
                        "city"
                    ),

                    "latitude": geo.get(
                        "latitude"
                    ),

                    "longitude": geo.get(
                        "longitude"
                    ),

                    "isp": geo.get(
                        "isp"
                    ),

                    "organization": (
                        geo.get(
                            "organization"
                        )
                    ),

                    "asn": geo.get(
                        "asn"
                    ),
                })

        except Exception as e:

            print(
                "IP geolocation error:",
                ip,
                e
            )

    return locations


def get_domain_enrichment(domain):

    domain = str(
        domain
    ).strip()

    resolved_ips = (
        resolve_domain_to_ips(
            domain
        )
    )

    locations = (
        geolocate_ips(
            resolved_ips
        )
    )

    return {

        "domain": domain,

        "resolved_ips": (
            resolved_ips
        ),

        "locations": locations,
    }


def get_url_enrichment(url):

    try:

        parsed = urlparse(
            url
        )

        domain = parsed.hostname

        if not domain:

            return {
                "domain": None,
                "resolved_ips": [],
                "locations": []
            }

        result = (
            get_domain_enrichment(
                domain
            )
        )

        return {

            "domain": domain,

            "resolved_ips": (
                result.get(
                    "resolved_ips",
                    []
                )
            ),

            "locations": (
                result.get(
                    "locations",
                    []
                )
            ),
        }

    except Exception as e:

        print(
            "URL enrichment error:",
            e
        )

        return {
            "domain": None,
            "resolved_ips": [],
            "locations": []
        }