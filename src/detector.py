from collections import defaultdict
from datetime import timedelta
import logging

from config.settings import (
    THRESHOLD,
    WINDOW_MINUTES,
    SPRAY_THRESHOLD,
    SPRAY_WINDOW_MINUTES,
    TRAVEL_THRESHOLD,
    TRAVEL_WINDOW_MINUTES,
)

logger = logging.getLogger(__name__)

SIGMA_RULES = {
    "brute_force": {
        "title": "Brute Force Detection",
        "id": "bf-001",
        "description": "Multiple failed logins from a single IP within a time window",
        "mitre": "T1110.001",
        "logsource": {"product": "linux", "service": "auth"},
        "detection": {
            "condition": "failed_logins_per_ip",
            "threshold": THRESHOLD,
            "window_minutes": WINDOW_MINUTES,
        },
        "severity": "high",
    },
    "password_spraying": {
        "title": "Password Spraying Detection",
        "id": "ps-001",
        "description": "Single IP attempting logins against many different users",
        "mitre": "T1110.003",
        "logsource": {"product": "linux", "service": "auth"},
        "detection": {
            "condition": "many_users_per_ip",
            "threshold": SPRAY_THRESHOLD,
            "window_minutes": SPRAY_WINDOW_MINUTES,
        },
        "severity": "high",
    },
    "impossible_travel": {
        "title": "Impossible Travel Detection",
        "id": "it-001",
        "description": "Same user logging in successfully from multiple IPs in a short time window",
        "mitre": "T1078",
        "logsource": {"product": "linux", "service": "auth"},
        "detection": {
            "condition": "many_ips_per_user",
            "threshold": TRAVEL_THRESHOLD,
            "window_minutes": TRAVEL_WINDOW_MINUTES,
        },
        "severity": "medium",
    },
}


def _get_window(times, index, window_minutes):
    t0 = times[index]
    return [t for t in times if t0 <= t <= t0 + timedelta(minutes=window_minutes)]


def detect_bruteforce(logs, threshold=THRESHOLD, window_minutes=WINDOW_MINUTES):
    """Detect brute-force login attempts (bf-001 / T1110.001).

    Flags any source IP with >= threshold failed logins within window_minutes.
    """
    rule = SIGMA_RULES["brute_force"]
    alerts = []
    attempts = defaultdict(list)

    for log in logs:
        if log["status"] == "FAILED":
            attempts[log["ip"]].append(log["timestamp"])

    for ip, times in attempts.items():
        times.sort()
        for i in range(len(times)):
            window = _get_window(times, i, window_minutes)
            if len(window) >= threshold:
                alerts.append({
                    "ip": ip,
                    "user": None,
                    "count": len(window),
                    "start_time": window[0],
                    "rule": rule["title"],
                    "rule_id": rule["id"],
                    "mitre": rule["mitre"],
                    "sigma_severity": rule["severity"],
                })
                logger.info("[%s] Brute force from %s (%d attempts)", rule["id"], ip, len(window))
                break

    return alerts


def detect_password_spraying(logs, threshold=SPRAY_THRESHOLD, window_minutes=SPRAY_WINDOW_MINUTES):
    """Detect password-spraying attacks (ps-001 / T1110.003).

    Flags any source IP targeting >= threshold distinct users within window_minutes.
    """
    rule = SIGMA_RULES["password_spraying"]
    alerts = []
    attempts = defaultdict(list)

    for log in logs:
        if log["status"] == "FAILED":
            attempts[log["ip"]].append((log["timestamp"], log["user"]))

    for ip, entries in attempts.items():
        entries.sort(key=lambda x: x[0])
        times = [e[0] for e in entries]
        for i in range(len(times)):
            window_entries = [
                e for e in entries
                if times[i] <= e[0] <= times[i] + timedelta(minutes=window_minutes)
            ]
            distinct_users = set(e[1] for e in window_entries)
            if len(distinct_users) >= threshold:
                alerts.append({
                    "ip": ip,
                    "user": None,
                    "count": len(window_entries),
                    "distinct_users": sorted(distinct_users),
                    "start_time": window_entries[0][0],
                    "rule": rule["title"],
                    "rule_id": rule["id"],
                    "mitre": rule["mitre"],
                    "sigma_severity": rule["severity"],
                })
                logger.info("[%s] Password spraying from %s targeting %s", rule["id"], ip, sorted(distinct_users))
                break

    return alerts


def detect_impossible_travel(logs, threshold=TRAVEL_THRESHOLD, window_minutes=TRAVEL_WINDOW_MINUTES):
    """Detect impossible-travel logins (it-001 / T1078).

    Flags any user seen logging in successfully from >= threshold distinct IPs
    within window_minutes. Uses SUCCESS events only - impossible travel is a
    valid-account abuse pattern, not a failed-login pattern.
    """
    rule = SIGMA_RULES["impossible_travel"]
    alerts = []
    attempts = defaultdict(list)

    for log in logs:
        if log["status"] == "SUCCESS":
            attempts[log["user"]].append((log["timestamp"], log["ip"]))

    for user, entries in attempts.items():
        entries.sort(key=lambda x: x[0])
        times = [e[0] for e in entries]
        for i in range(len(times)):
            window_entries = [
                e for e in entries
                if times[i] <= e[0] <= times[i] + timedelta(minutes=window_minutes)
            ]
            distinct_ips = set(e[1] for e in window_entries)
            if len(distinct_ips) >= threshold:
                alerts.append({
                    "ip": None,
                    "user": user,
                    "count": len(window_entries),
                    "distinct_ips": sorted(distinct_ips),
                    "start_time": window_entries[0][0],
                    "rule": rule["title"],
                    "rule_id": rule["id"],
                    "mitre": rule["mitre"],
                    "sigma_severity": rule["severity"],
                })
                logger.info("[%s] Impossible travel for '%s' across %s", rule["id"], user, sorted(distinct_ips))
                break

    return alerts


def run_all_detections(
    logs,
    threshold=THRESHOLD,
    window_minutes=WINDOW_MINUTES,
    spray_threshold=SPRAY_THRESHOLD,
    spray_window_minutes=SPRAY_WINDOW_MINUTES,
    travel_threshold=TRAVEL_THRESHOLD,
    travel_window_minutes=TRAVEL_WINDOW_MINUTES,
):
    """Run all SIGMA detection rules and return deduplicated alerts."""
    all_alerts = (
        detect_bruteforce(logs, threshold, window_minutes)
        + detect_password_spraying(logs, spray_threshold, spray_window_minutes)
        + detect_impossible_travel(logs, travel_threshold, travel_window_minutes)
    )

    seen = set()
    deduped = []
    for alert in all_alerts:
        key = (alert.get("ip"), alert.get("user"), alert["rule_id"])
        if key not in seen:
            seen.add(key)
            deduped.append(alert)

    logger.info("Total alerts after deduplication: %d", len(deduped))
    return deduped
