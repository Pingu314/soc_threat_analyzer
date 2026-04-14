import logging
import requests
import ipaddress

logger = logging.getLogger(__name__)

_cache = {}


def is_private_ip(ip: str) -> bool:
    """Return True if the given IP address is in a private (RFC 1918) range.

    Args:
        ip: IPv4 or IPv6 address string.

    Returns:
        True if private/loopback, False otherwise. Returns False for
        unparseable input.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def get_ip_info(ip: str) -> dict | None:
    """Enrich an IP address with geolocation and organisation data via ipinfo.io.

    Private IPs are handled locally without an API call. Results are cached
    in-memory for the lifetime of the process to avoid redundant requests.

    Args:
        ip: IPv4 address string to look up.

    Returns:
        A dict with keys 'ip', 'country', and 'org', or None on API failure.
        Private IPs return country='PRIVATE' and org='Internal Network'.
    """
    if is_private_ip(ip):
        logger.debug("Skipping API call for private IP: %s", ip)
        return {"ip": ip, "country": "PRIVATE", "org": "Internal Network"}

    if ip in _cache:
        logger.debug("Cache hit for IP: %s", ip)
        return _cache[ip]

    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            data = response.json()
            result = {"ip": ip,
                      "country": data.get("country", "Unknown"),
                      "org": data.get("org", "Unknown")}
            _cache[ip] = result
            return result
        else:
            logger.warning("ipinfo.io returned status %d for IP %s", response.status_code, ip)
            return None
    except requests.exceptions.Timeout:
        logger.warning("Timeout fetching threat intel for IP: %s", ip)
        return None
    except requests.exceptions.RequestException as e:
        logger.error("Request error fetching threat intel for IP %s: %s", ip, e)
        return None
    except Exception as e:
        logger.error("Unexpected error in get_ip_info for IP %s: %s", ip, e)
        return None