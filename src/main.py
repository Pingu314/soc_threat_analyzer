import csv
import logging
import os

from src.parser import parse_log
from src.detector import detect_bruteforce
from src.threat_intel import get_ip_info
from src.risk_scoring import calculate_risk, get_severity, map_mitre
from config.settings import THRESHOLD, WINDOW_MINUTES

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def run_pipeline():
    logger.info("Starting SOC pipeline...")
    logs = parse_log("data/logs.txt")
    logger.info(f"Parsed {len(logs)} log entries.")
    alerts = detect_bruteforce(logs, THRESHOLD, WINDOW_MINUTES)
    logger.info(f"Detected {len(alerts)} brute-force alert(s).")

    final_alerts = []

    for alert in alerts:
        intel = get_ip_info(alert["ip"])
        risk = calculate_risk(alert, intel)

        result = {"ip": alert["ip"],
                  "count": alert["count"],
                  "country": intel["country"] if intel else "Unknown",
                  "org": intel["org"] if intel else "Unknown",
                  "risk_score": risk,
                  "severity": get_severity(risk),
                  "mitre_technique": map_mitre(alert.get("rule"))}

        logger.info(f"Alert: {result}")
        final_alerts.append(result)

    return final_alerts


if __name__ == "__main__":
    alerts = run_pipeline()

    os.makedirs("output", exist_ok=True)

    fieldnames = ["ip", "count", "country", "org", "risk_score", "severity", "mitre_technique"]

    with open("output/alerts.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(alerts)

    logger.info(f"Saved {len(alerts)} alert(s) to out")