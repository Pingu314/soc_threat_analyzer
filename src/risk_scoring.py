import logging

from config.settings import (SUSPICIOUS_COUNTRIES, LOGIN_EVENT_WEIGHT, SUSPICIOUS_COUNTRY_SCORE, TOR_SCORE,
                             SPRAY_USER_WEIGHT, TRAVEL_IP_WEIGHT, SEVERITY_HIGH, SEVERITY_MEDIUM)

logger = logging.getLogger(__name__)

MITRE_MAPPING = {"T1110.001": "Brute Force: Password Guessing",
                 "T1110.003": "Brute Force: Password Spraying",
                 "T1078":     "Valid Accounts: Impossible Travel"}

def calculate_risk(alert: dict, intel: dict | None) -> int:
    """Calculate a numeric risk score for an alert using threat intelligence data.

    Scoring factors (weights configured in config/settings.py):
        - Each login event for this alert:  +LOGIN_EVENT_WEIGHT
        - Suspicious source country:        +SUSPICIOUS_COUNTRY_SCORE
        - Tor exit node detected in org:    +TOR_SCORE
        - Each distinct user (spraying):    +SPRAY_USER_WEIGHT per user
        - Each distinct IP (impossible travel): +TRAVEL_IP_WEIGHT per IP

    Args:
        alert: An alert dict produced by one of the detector functions.
        intel: IP enrichment data from threat_intel.get_ip_info, or None.

    Returns:
        An integer risk score. Higher values indicate greater severity.
    """
    score = 0

    score += alert["count"] * LOGIN_EVENT_WEIGHT

    if intel:
        if intel.get("country") in SUSPICIOUS_COUNTRIES:
            logger.debug(f"Suspicious country for {alert.get('ip')}: {intel['country']}")
            score += SUSPICIOUS_COUNTRY_SCORE

        if "Tor" in intel.get("org", ""):
            logger.debug(f"Tor exit node detected for {alert.get('ip')}")
            score += TOR_SCORE

        if intel.get("country") == "PRIVATE":
            # Private/internal IPs are scored normally — internal lateral movement
            # is still a risk and should not be silently discarded.
            logger.info(f"Internal IP flagged: {alert.get('ip')}")

    if "distinct_users" in alert:
        score += len(alert["distinct_users"]) * SPRAY_USER_WEIGHT

    if "distinct_ips" in alert:
        score += len(alert["distinct_ips"]) * TRAVEL_IP_WEIGHT

    return score

def get_severity(score: int) -> str:
    """Convert a numeric risk score into a severity label.

    Thresholds are defined by SEVERITY_HIGH and SEVERITY_MEDIUM in settings.py.

    Args:
        score: Integer risk score from calculate_risk.

    Returns:
        'HIGH', 'MEDIUM', or 'LOW'.
    """
    if score >= SEVERITY_HIGH:
        return "HIGH"
    if score >= SEVERITY_MEDIUM:
        return "MEDIUM"
    return "LOW"


def map_mitre(mitre_id: str | None) -> str:
    """Map a MITRE ATT&CK technique ID to its human-readable name.

    Args:
        mitre_id: A MITRE technique ID string (e.g. 'T1110.001'), or None.

    Returns:
        The technique name string, the original ID if not in the mapping,
        or 'UNKNOWN' if mitre_id is None.
    """
    if mitre_id is None:
        return "UNKNOWN"
    return MITRE_MAPPING.get(mitre_id, mitre_id)