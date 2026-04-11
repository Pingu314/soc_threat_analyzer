import logging

from config.settings import (SUSPICIOUS_COUNTRIES, FAILED_LOGIN_WEIGHT,
                             SUSPICIOUS_COUNTRY_SCORE, TOR_SCORE,
                             SPRAY_USER_WEIGHT, TRAVEL_IP_WEIGHT,
                             SEVERITY_HIGH, SEVERITY_MEDIUM)

logger = logging.getLogger(__name__)

MITRE_MAPPING = {"T1110.001": "Brute Force: Password Guessing",
                 "T1110.003": "Brute Force: Password Spraying",
                 "T1078":     "Valid Accounts: Impossible Travel"}

def calculate_risk(alert: dict, intel: dict | None) -> int:
    score = 0

    score += alert["count"] * FAILED_LOGIN_WEIGHT

    if intel:
        if intel.get("country") in SUSPICIOUS_COUNTRIES:
            logger.debug(f"Suspicious country for {alert.get('ip')}: {intel['country']}")
            score += SUSPICIOUS_COUNTRY_SCORE

        if "Tor" in intel.get("org", ""):
            logger.debug(f"Tor exit node detected for {alert.get('ip')}")
            score += TOR_SCORE

        if intel.get("country") == "PRIVATE":
            logger.info(f"Internal IP flagged: {alert.get('ip')}")

    if "distinct_users" in alert:
        score += len(alert["distinct_users"]) * SPRAY_USER_WEIGHT

    if "distinct_ips" in alert:
        score += len(alert["distinct_ips"]) * TRAVEL_IP_WEIGHT

    return score

def get_severity(score: int) -> str:
    if score >= SEVERITY_HIGH:
        return "HIGH"
    if score >= SEVERITY_MEDIUM:
        return "MEDIUM"
    return "LOW"


def map_mitre(mitre_id: str | None) -> str:
    if mitre_id is None:
        return "UNKNOWN"
    return MITRE_MAPPING.get(mitre_id, mitre_id)