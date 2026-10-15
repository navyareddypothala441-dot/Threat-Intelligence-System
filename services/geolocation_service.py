import requests


def get_ip_geolocation(ip):
    """
    Free geolocation using ip-api.com.

    Only use for public IP addresses.
    """

    try:
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields="
            "status,message,country,"
            "regionName,city,lat,lon,"
            "isp,org,as,query"
        )

        response = requests.get(
            url,
            timeout=15
        )

        response.raise_for_status()

        data = response.json()

        if data.get(
            "status"
        ) != "success":

            return {
                "error": data.get(
                    "message",
                    "Geolocation failed"
                )
            }

        as_field = data.get(
            "as",
            ""
        )

        asn = None

        if isinstance(
            as_field,
            str
        ):
            parts = as_field.split()

            if parts:
                first = parts[0]

                if first.startswith(
                    "AS"
                ):
                    try:
                        asn = int(
                            first[2:]
                        )

                    except ValueError:
                        pass

        return {
            "country": data.get(
                "country"
            ),

            "region": data.get(
                "regionName"
            ),

            "city": data.get(
                "city"
            ),

            "latitude": data.get(
                "lat"
            ),

            "longitude": data.get(
                "lon"
            ),

            "isp": data.get(
                "isp"
            ),

            "organization": data.get(
                "org"
            ),

            "asn": asn
        }

    except Exception as e:
        return {
            "error": str(e)
        }