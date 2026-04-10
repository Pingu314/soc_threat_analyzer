SUSPICIOUS_COUNTRIES = ["RU", "CN", "KP"]
SUSPICIOUS_ORGS = ["Tor", "Unknown"]
MITRE_MAPPING = {"Brute Force Detection": "T1110"}

def calculate_risk(alert, intel):
    score = 0

    # Failed login weight
    score += alert["count"] * 3

    # Country risk
    if intel and intel["country"] in SUSPICIOUS_COUNTRIES:
        score += 5

    if intel and intel["org"]:
        if "Tor" in intel["org"]:
            score += 5

    return score

def get_severity(score):
    if score >=12:
        return "HIGH"
    elif score >= 6:
        return "MEDIUM"
    return "LOW"

def map_mitre(rule_name):
    return MITRE_MAPPING.get(rule_name, "UNKNOWN")
