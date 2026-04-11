import logging

logger = logging.getLogger(__name__)

SUSPICIOUS_COUNTRIES = ["RU", "CN", "KP"]
SUSPICIOUS_ORGS = ["Tor", "Unknown"]
MITRE_MAPPING = {"Brute Force Detection": "T1110"}

def calculate_risk(alert: dict, intel: dict | None) -> int:
    score = 0

    # Failed login weight
    score += alert["count"] * 3

    if intel:
        # Country risk
        if intel.get("country") in SUSPICIOUS_COUNTRIES:
            logger.debug(f"Suspicious country for {alert['ip']}: {intel['country']}")
            score += 5

        # Org risk
        org = intel.get("org", "")
        if "Tor" in org:
            logger.debug(f"Tor exit node detected for {alert['ip']}")
            score += 5

        if intel.get("country") == "PRIVATE":
            logger.info(f"Internal IP flagged: {alert['ip']}")

    return score

def get_severity(score: int) -> str:
    if score >= 12:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"

def map_mitre(rule_name: str | None) -> str:
    if rule_name is None:
        return "UNKNOWN"
    return MITRE_MAPPING.get(rule_name, "UNKNOWN")