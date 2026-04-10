SUSPICIOUS_COUNTRIES = ["RU", "CN", "KP"]

def calculate_risk(alert, intel):
    score = 0

    # Failed login weight
    score += alert["count"] * 2

    # Country risk
    if intel and intel["country"] in SUSPICIOUS_COUNTRIES:
        score += 5

    return score

def get_severity(score):
    if score >=10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    return "LOW"
