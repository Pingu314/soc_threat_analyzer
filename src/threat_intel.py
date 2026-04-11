import logging
import requests
import ipaddress

logger = logging.getLogger(__name__)

_cache = {}

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_ip_info(ip: str) -> dict | None:
    if is_private_ip(ip):
        logger.debug(f"Skipping API call for private IP: {ip}")
        return {"ip": ip,
                "country": "PRIVATE",
                "org": "Internal Network"}

    if ip in _cache:
        logger.debug(f"Cache hit for IP: {ip}")
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
            logger.warning(f"ipinfo.io returned status {response.status_code} for IP {ip}")
            return None

    except requests.exceptions.Timeout:
        logger.warning(f"Timeout fetching threat intel for IP: {ip}")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error fetching threat intel for IP {ip}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in get_ip_info for IP {ip}: {e}")