from datetime import datetime, timedelta

from src.detector import (
    detect_bruteforce,
    detect_impossible_travel,
    detect_password_spraying,
    run_all_detections,
)


class TestDetectBruteforce:
    @staticmethod
    def _make_logs(ip, count, minutes_apart=0.1):
        base = datetime(2026, 1, 1, 10, 0, 0)
        return [{"ip": ip,
                 "user": "admin",
                 "status": "FAILED",
                 "timestamp": base + timedelta(minutes=i * minutes_apart)}
                for i in range(count)]

    def test_triggers_at_threshold(self):
        alerts = detect_bruteforce(self._make_logs("1.2.3.4", 3), threshold=3, window_minutes=5)
        assert len(alerts) == 1
        assert alerts[0]["ip"] == "1.2.3.4"
        assert alerts[0]["mitre"] == "T1110.001"

    def test_no_alert_below_threshold(self):
        assert detect_bruteforce(self._make_logs("1.2.3.4", 2), threshold=3, window_minutes=5) == []

    def test_outside_time_window(self):
        assert (
            detect_bruteforce(self._make_logs("1.2.3.4", 3, minutes_apart=10),
                               threshold=3, window_minutes=5) == []
        )

    def test_success_not_counted(self):
        base = datetime(2026, 1, 1, 10, 0, 0)
        logs = [
            {"ip": "1.2.3.4", "user": "admin", "status": "FAILED",
             "timestamp": base},
            {"ip": "1.2.3.4", "user": "admin", "status": "SUCCESS",
             "timestamp": base + timedelta(seconds=10)},
            {"ip": "1.2.3.4", "user": "admin", "status": "FAILED",
             "timestamp": base + timedelta(seconds=20)},
        ]
        assert detect_bruteforce(logs, threshold=3, window_minutes=5) == []


class TestDetectPasswordSpraying:
    def test_detects_spraying(self, spray_logs):
        alerts = detect_password_spraying(spray_logs)
        assert len(alerts) == 1
        assert alerts[0]["mitre"] == "T1110.003"
        assert set(alerts[0]["distinct_users"]) == {"user_0", "user_1", "user_2"}

    def test_no_alert_single_user(self, base_time):
        logs = [{"ip": "1.2.3.4",
                 "user": "admin",
                 "status": "FAILED",
                 "timestamp": base_time + timedelta(seconds=i)}
                for i in range(5)]
        assert detect_password_spraying(logs) == []

    def test_rule_id(self, spray_logs):
        alerts = detect_password_spraying(spray_logs)
        assert alerts[0]["rule_id"] == "ps-001"


class TestDetectImpossibleTravel:
    def test_detects_travel(self, travel_logs):
        alerts = detect_impossible_travel(travel_logs)
        assert len(alerts) == 1
        assert alerts[0]["mitre"] == "T1078"
        assert alerts[0]["user"] == "admin"

    def test_no_alert_single_ip(self, base_time):
        logs = [{"ip": "1.2.3.4",
                 "user": "admin",
                 "status": "SUCCESS",
                 "timestamp": base_time + timedelta(seconds=i)}
                for i in range(3)]
        assert detect_impossible_travel(logs) == []

    def test_failed_logins_not_counted(self, base_time):
        logs = [{"ip": f"10.0.0.{i+1}",
                 "user": "admin",
                 "status": "FAILED",
                 "timestamp": base_time + timedelta(minutes=i)}
                for i in range(3)]
        assert detect_impossible_travel(logs) == []

    def test_rule_id(self, travel_logs):
        alerts = detect_impossible_travel(travel_logs)
        assert alerts[0]["rule_id"] == "it-001"


class TestRunAllDetections:
    def test_deduplication(self, brute_force_logs):
        alerts = run_all_detections(brute_force_logs + brute_force_logs)
        bf_alerts = [a for a in alerts if a.get("ip") == "185.220.101.1"]
        assert len(bf_alerts) == 1

    def test_all_rules_fire(self, mixed_logs):
        alerts = run_all_detections(mixed_logs)
        rule_ids = {a["rule_id"] for a in alerts}
        assert "bf-001" in rule_ids
        assert "ps-001" in rule_ids
        assert "it-001" in rule_ids
