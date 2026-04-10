import csv

from src.risk_scoring import get_severity
from src.parser import parse_log
from src.detector import detect_bruteforce
from src.threat_intel import get_ip_info
from src.risk_scoring import calculate_risk
from config.settings import THRESHOLD, WINDOW_MINUTES

logs = parse_log("data/logs.txt")
alerts = detect_bruteforce(logs, THRESHOLD, WINDOW_MINUTES)

final_alerts = []

print("\n SOC Alerts:\n")

for alert in alerts:
    intel = get_ip_info(alert["ip"])
    risk = calculate_risk(alert, intel)

    result = {"ip": alert["ip"],
              "count": alert["count"],
              "country": intel["country"] if intel else "Unknown",
              "org": intel["org"] if intel else "Unknown",
              "risk_score": risk,
              "severity": get_severity(risk)}

    final_alerts.append(result)
    print(result)

# Save to CSV
fieldnames = ["ip", "count", "country", "org", "risk_score", "severity"]

with open("output/alerts.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(final_alerts)