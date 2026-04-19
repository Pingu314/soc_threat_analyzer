import csv
import logging
import os
import pathlib

from src.parser import parse_log
from src.detector import run_all_detections
from src.threat_intel import get_ip_info
from src.risk_scoring import calculate_risk, get_severity

LOG_PATH = pathlib.Path(__file__).parent.parent / "data" / "logs.txt"

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def run_pipeline() -> list:
    """Run the full SOC detection pipeline end-to-end.

    Steps:
        1. Parse authentication logs from data/logs.txt.
        2. Run all SIGMA detection rules (brute-force, spraying, impossible travel).
        3. Enrich each alert with IP geolocation via ipinfo.io.
        4. Calculate a risk score and severity label for each alert.
        5. Collect and return all enriched alert dicts.

    Returns:
        A list of fully enriched and scored alert dicts, ready for export or display.
    """
    logger.info("Starting SOC pipeline...")
    logs = parse_log("data/logs.txt")
    logger.info(f"Parsed {len(logs)} log entries.")

    alerts = run_all_detections(logs)
    logger.info(f"Detected {len(alerts)} alert(s) across all rules.")

    final_alerts = []

    for alert in alerts:
        ip = alert.get("ip")
        intel = get_ip_info(ip) if ip else None
        risk = calculate_risk(alert, intel)

        result = {"rule_id":        alert["rule_id"],
                  "rule":           alert["rule"],
                  "mitre":          alert["mitre"],
                  "sigma_severity": alert["sigma_severity"],
                  "ip":             ip or "multiple",
                  "user":           alert.get("user") or "multiple",
                  "count":          alert["count"],
                  "country":        intel["country"] if intel else "Unknown",
                  "org":            intel["org"] if intel else "Unknown",
                  "risk_score":     risk,
                  "severity":       get_severity(risk)}

        if "distinct_users" in alert:
            result["distinct_users"] = ", ".join(alert["distinct_users"])
        if "distinct_ips" in alert:
            result["distinct_ips"] = ", ".join(alert["distinct_ips"])

        final_alerts.append(result)

    return final_alerts


if __name__ == "__main__":
    alerts = run_pipeline()

    for alert in alerts:
        print(alert)

    os.makedirs("output", exist_ok=True)

    fieldnames = ["rule_id", "rule", "mitre", "sigma_severity", "ip", "user", "count", "country", "org",
                  "risk_score", "severity", "distinct_users", "distinct_ips"]

    with open("output/alerts.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(alerts)

    logger.info(f"Saved {len(alerts)} alert(s) to output/alerts.csv")