from collections import defaultdict
from datetime import timedelta

SIGMA_RULE = {"title": "Brute Force Detection",
              "logsource": {"product": "linux",
                            "service": "auth"},
              "detection": {"condition": "failed_logins >= threshold within time_window"}}

def detect_bruteforce(logs, threshold=3, window_minutes=5):
    alerts = []
    attempts = defaultdict(list)

    for log in logs:
        if log["status"] == "FAILED":
            attempts[log["ip"]].append(log["timestamp"])

    for ip, times in attempts.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times if times[i] <= t <= times[i] + timedelta(minutes=window_minutes)]
            if len(window) >= threshold:
                alerts.append({"ip": ip,
                               "count": len(window),
                               "start_time": window[0],
                               "rule": SIGMA_RULE["title"]})
                break

    return alerts
