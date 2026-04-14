from collections import defaultdict
from datetime import timedelta
import logging

from config.settings import THRESHOLD, WINDOW_MINUTES, SPRAY_THRESHOLD, SPRAY_WINDOW_MINUTES, TRAVEL_THRESHOLD, TRAVEL_WINDOW_MINUTES

logger = logging.getLogger(__name__)

SIGMA_RULES = {
      "brute_force": {
                "title": "Brute Force Detection",
                "id": "bf-001",
                "description": "Multiple failed logins from a single IP within a time window",
                "mitre": "T1110.001",
                "logsource": {"product": "linux", "service": "auth"},
                "detection": {"condition": "failed_logins_per_ip", "threshold": THRESHOLD, "window_minutes": WINDOW_MINUTES},
                "severity": "high",
      },
      "password_spraying": {
                "title": "Password Spraying Detection",
                "id": "ps-001",
                "description": "Single IP attempting logins against many different users",
                "mitre": "T1110.003",
                "logsource": {"product": "linux", "service": "auth"},
                "detection": {"condition": "many_users_per_ip", "threshold": SPRAY_THRESHOLD, "window_minutes": SPRAY_WINDOW_MINUTES},
                "severity": "high",
      },
      "impossible_travel": {
                "title": "Impossible Travel Detection",
                "id": "it-001",
                "description": "Same user logging in successfully from multiple IPs in a short time window",
                "mitre": "T1078",
                "logsource": {"product": "linux", "service": "auth"},
                "detection": {"condition": "many_ips_per_user", "threshold": TRAVEL_THRESHOLD, "window_minutes": TRAVEL_WINDOW_MINUTES},
                "severity": "medium",
      },
}


def _get_window(times: list, index: int, window_minutes: int) -> list:
      """Return all timestamps in 'times' that fall within a sliding window starting at index.

          Args:
                  times: Sorted list of datetime objects.
                          index: Starting index; defines the window's anchor time t0.
                                  window_minutes: Width of the window in minutes.

                                      Returns:
                                              A list of datetimes t such that t0 <= t <= t0 + window_minutes.
                                                  """
      t0 = times[index]
      return [t for t in times if t0 <= t <= t0 + timedelta(minutes=window_minutes)]


def detect_bruteforce(
      logs: list,
      threshold: int = THRESHOLD,
      window_minutes: int = WINDOW_MINUTES,
) -> list:
      """Detect brute-force login attempts (SIGMA rule bf-001 / MITRE T1110.001).

          Flags any source IP that accumulates >= threshold failed logins within a
              rolling window of window_minutes.

                  Args:
                          logs: Parsed log entries (list of dicts from parser.parse_log).
                                  threshold: Minimum number of failures to trigger an alert.
                                          window_minutes: Length of the detection window in minutes.

                                              Returns:
                                                      A list of alert dicts, one per triggering IP.
                                                          """
      rule = SIGMA_RULES["brute_force"]
      alerts = []
      attempts: dict = defaultdict(list)

    for log in logs:
              if log["status"] == "FAILED":
                            attempts[log["ip"]].append(log["timestamp"])

          for ip, times in attempts.items():
                    times.sort()
                    for i in range(len(times)):
                                  window = _get_window(times, i, window_minutes)
                                  if len(window) >= threshold:
                                                    alerts.append(
                                                                          {
                                                                                                    "ip": ip,
                                                                                                    "user": None,
                                                                                                    "count": len(window),
                                                                                                    "start_time": window[0],
                                                                                                    "rule": rule["title"],
                                                                                                    "rule_id": rule["id"],
                                                                                                    "mitre": rule["mitre"],
                                                                                                    "sigma_severity": rule["severity"],
                                                                          }
                                                    )
                                                    logger.info(f"[{rule['id']}] Brute force from {ip} ({len(window)} attempts)")
                                                    break

                          return alerts


def detect_password_spraying(
      logs: list,
      threshold: int = SPRAY_THRESHOLD,
      window_minutes: int = SPRAY_WINDOW_MINUTES,
) -> list:
      """Detect password-spraying attacks (SIGMA rule ps-001 / MITRE T1110.003).

          Flags any source IP that targets >= threshold distinct usernames within a
              rolling window of window_minutes.

                  Args:
                          logs: Parsed log entries (list of dicts from parser.parse_log).
                                  threshold: Minimum number of distinct target users to trigger an alert.
                                          window_minutes: Length of the detection window in minutes.

                                              Returns:
                                                      A list of alert dicts, one per triggering IP.
                                                          """
    rule = SIGMA_RULES["password_spraying"]
    alerts = []
    attempts: dict = defaultdict(list)

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
                                        alerts.append(
                                                              {
                                                                                        "ip": ip,
                                                                                        "user": None,
                                                                                        "count": len(window_entries),
                                                                                        "distinct_users": sorted(distinct_users),
                                                                                        "start_time": window_entries[0][0],
                                                                                        "rule": rule["title"],
                                                                                        "rule_id": rule["id"],
                                                                                        "mitre": rule["mitre"],
                                                                                        "sigma_severity": rule["severity"],
                                                              }
                                        )
                                        logger.info(f"[{rule['id']}] Password spraying from {ip} targeting {sorted(distinct_users)}")
                                        break

              return alerts


def detect_impossible_travel(
      logs: list,
      threshold: int = TRAVEL_THRESHOLD,
      window_minutes: int = TRAVEL_WINDOW_MINUTES,
) -> list:
      """Detect impossible-travel logins (SIGMA rule it-001 / MITRE T1078).

          Flags any user account seen logging in *successfully* from >= threshold
              distinct source IPs within a rolling window of window_minutes.

                  Impossible travel is a credential-abuse pattern that only makes sense for
                      successful authentications — failed logins from many IPs are better covered
                          by brute-force or spraying rules.

                              Args:
                                      logs: Parsed log entries (list of dicts from parser.parse_log).
                                              threshold: Minimum number of distinct source IPs to trigger an alert.
                                                      window_minutes: Length of the detection window in minutes.

                                                          Returns:
                                                                  A list of alert dicts, one per triggering user account.
                                                                      """
    rule = SIGMA_RULES["impossible_travel"]
    alerts = []
    attempts: dict = defaultdict(list)

    # Track SUCCESS logins — impossible travel is a valid-account abuse pattern.
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
                                        alerts.append(
                                                              {
                                                                                        "ip": None,
                                                                                        "user": user,
                                                                                        "count": len(window_entries),
                                                                                        "distinct_ips": sorted(distinct_ips),
                                                                                        "start_time": window_entries[0][0],
                                                                                        "rule": rule["title"],
                                                                                        "rule_id": rule["id"],
                                                                                        "mitre": rule["mitre"],
                                                                                        "sigma_severity": rule["severity"],
                                                              }
                                        )
                                        logger.info(f"[{rule['id']}] Impossible travel for '{user}' across {sorted(distinct_ips)}")
                                        break

              return alerts


def run_all_detections(
      logs: list,
      threshold: int = THRESHOLD,
      window_minutes: int = WINDOW_MINUTES,
      spray_threshold: int = SPRAY_THRESHOLD,
      spray_window_minutes: int = SPRAY_WINDOW_MINUTES,
      travel_threshold: int = TRAVEL_THRESHOLD,
      travel_window_minutes: int = TRAVEL_WINDOW_MINUTES,
) -> list:
      """Run all SIGMA detection rules and return deduplicated alerts.

          Runs brute-force, password-spraying, and impossible-travel detections in
              sequence, then removes duplicate alerts keyed on (ip, user, rule_id).

                  All detection thresholds and windows can be overridden via parameters;
                      defaults come from config/settings.py.

                          Args:
                                  logs: Parsed log entries (list of dicts from parser.parse_log).
                                          threshold: Brute-force failure threshold.
                                                  window_minutes: Brute-force detection window in minutes.
                                                          spray_threshold: Password-spraying distinct-user threshold.
                                                                  spray_window_minutes: Password-spraying detection window in minutes.
                                                                          travel_threshold: Impossible-travel distinct-IP threshold.
                                                                                  travel_window_minutes: Impossible-travel detection window in minutes.

                                                                                      Returns:
                                                                                              A deduplicated list of alert dicts ready for enrichment and scoring.
                                                                                                  """
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

    logger.info(f"Total alerts after deduplication: {len(deduped)}")
    return deduped
