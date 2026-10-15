import whois
from datetime import datetime


def _safe_date(value):
    if value is None:
        return None

    if isinstance(
        value,
        list
    ):
        if not value:
            return None

        value = value[0]

    if isinstance(
        value,
        datetime
    ):
        return value.isoformat()

    return str(value)


def _safe_list(value):
    if value is None:
        return []

    if isinstance(
        value,
        list
    ):
        return value

    return [
        str(value)
    ]


def get_domain_whois(domain):
    try:
        info = whois.whois(
            domain
        )

        return {
            "domain_name":
                info.domain_name,

            "registrar":
                info.registrar,

            "creation_date":
                _safe_date(
                    info.creation_date
                ),

            "expiration_date":
                _safe_date(
                    info.expiration_date
                ),

            "updated_date":
                _safe_date(
                    info.updated_date
                ),

            "name_servers":
                _safe_list(
                    info.name_servers
                ),

            "status":
                _safe_list(
                    info.status
                ),

            "emails":
                _safe_list(
                    info.emails
                ),

            "org":
                getattr(
                    info,
                    "org",
                    None
                ),

            "country":
                getattr(
                    info,
                    "country",
                    None
                )
        }

    except Exception as e:
        return {
            "error": str(e)
        }