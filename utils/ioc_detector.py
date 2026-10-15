import re
import ipaddress
from urllib.parse import urlparse


def detect_ioc(ioc):
    """Detect the supported IOC type without changing the input value."""

    if ioc is None:
        return "Invalid IOC"

    ioc = str(ioc).strip()

    if not ioc:
        return "Invalid IOC"

    # ========================================================
    # IP ADDRESS (IPv4 / IPv6)
    # ========================================================
    try:
        ipaddress.ip_address(ioc)
        return "IP Address"
    except ValueError:
        pass

    # ========================================================
    # URL
    # ========================================================
    # urllib.parse is more reliable than a restrictive regex and supports
    # ports, paths, query strings, fragments and subdomains.
    try:
        parsed = urlparse(ioc)
        if (
            parsed.scheme.lower() in ("http", "https")
            and parsed.netloc
            and not any(ch.isspace() for ch in ioc)
        ):
            return "URL"
    except (TypeError, ValueError):
        pass

    # ========================================================
    # HASHES
    # ========================================================
    if re.fullmatch(r"[a-fA-F0-9]{32}", ioc):
        return "MD5 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{40}", ioc):
        return "SHA1 Hash"

    if re.fullmatch(r"[a-fA-F0-9]{64}", ioc):
        return "SHA256 Hash"

    # ========================================================
    # DOMAIN
    # ========================================================
    # Permit normal DNS labels while rejecting URLs, whitespace and
    # labels that begin/end with a hyphen.
    domain_pattern = re.compile(
        r"^(?=.{1,253}\.?$)"
        r"(?:"
        r"(?!-)"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"\."
        r")+"
        r"[A-Za-z]{2,63}\.?$"
    )

    if domain_pattern.fullmatch(ioc):
        return "Domain"

    return "Unknown"
