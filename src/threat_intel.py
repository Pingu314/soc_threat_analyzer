import requests

def get_ip_info(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=3)

        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "country": data.get("country"),
                "org": data.get("org")
            }
    except:
        return None