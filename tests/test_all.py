from unittest.mock import patch
from datetime import datetime, timedelta
from src.risk_scoring import calculate_risk, get_severity, map_mitre
from src.detector import (detect_bruteforce, detect_password_spraying, detect_impossible_travel, run_all_detections)
from src.parser import parse_log
from src.threat_intel import is_private_ip
from src.main import run_pipeline


# risk_scoring
class TestGetSeverity:
    def test_low(self):
        assert get_severity(0) == "LOW"
        assert get_severity(5) == "LOW"

    def test_medium(self):
        assert get_severity(6) == "MEDIUM"
        assert get_severity(11) == "MEDIUM"

    def test_high(self):
        assert get_severity(12) == "HIGH"
        assert get_severity(99) == "HIGH"


class TestCalculateRisk:
    def test_base_score(self):
        assert calculate_risk({"ip": "1.2.3.4", "count": 3}, None) == 9

    def test_suspicious_country(self):
        alert = {"ip": "1.2.3.4", "count": 3}
        intel = {"ip": "1.2.3.4", "country": "RU", "org": "SomeISP"}
        assert calculate_risk(alert, intel) == 14

    def test_tor_node(self):
        alert = {"ip": "1.2.3.4", "count": 3}
        intel = {"ip": "1.2.3.4", "country": "DE", "org": "Tor Network"}
        assert calculate_risk(alert, intel) == 14

    def test_no_intel(self):
        assert calculate_risk({"ip": "1.2.3.4", "count": 2}, None) == 6

    def test_spray_bonus(self):
        alert = {"ip": "1.2.3.4", "count": 3, "distinct_users": ["admin", "root", "guest"]}
        score = calculate_risk(alert, None)
        assert score == 9 + 6  # base + 3 users * 2

    def test_travel_bonus(self):
        alert = {"user": "admin", "count": 2, "distinct_ips": ["1.1.1.1", "2.2.2.2"]}
        score = calculate_risk(alert, None)
        assert score == 6 + 4  # base + 2 IPs * 2


class TestMapMitre:
    def test_brute_force_subtechnique(self):
        assert map_mitre("T1110.001") == "Brute Force: Password Guessing"

    def test_spraying_subtechnique(self):
        assert map_mitre("T1110.003") == "Brute Force: Password Spraying"

    def test_impossible_travel(self):
        assert map_mitre("T1078") == "Valid Accounts: Impossible Travel"

    def test_unknown(self):
        assert map_mitre("T9999") == "T9999"

    def test_none(self):
        assert map_mitre(None) == "UNKNOWN"


# detector
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
        assert (detect_bruteforce(self._make_logs("1.2.3.4", 3, minutes_apart=10), threshold=3, window_minutes=5) == [])

    def test_success_not_counted(self):
        base = datetime(2026, 1, 1, 10, 0, 0)
        logs = [{"ip": "1.2.3.4", "user": "admin", "status": "FAILED", "timestamp": base},
                {"ip": "1.2.3.4", "user": "admin", "status": "SUCCESS", "timestamp": base + timedelta(seconds=10)},
                {"ip": "1.2.3.4", "user": "admin", "status": "FAILED", "timestamp": base + timedelta(seconds=20)}]
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
        assert len(bf_alerts) == 1  # same IP+rule_id combo must not appear twice

    def test_all_rules_fire(self, mixed_logs):
        alerts = run_all_detections(mixed_logs)
        rule_ids = {a["rule_id"] for a in alerts}
        assert "bf-001" in rule_ids
        assert "ps-001" in rule_ids
        assert "it-001" in rule_ids


# threat_intel
class TestIsPrivateIp:
    def test_private_ranges(self):
        assert is_private_ip("192.168.1.10") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True

    def test_public_ips(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("185.220.101.1") is False

    def test_invalid_ip(self):
        assert is_private_ip("not_an_ip") is False


# parser
class TestParseLog:
    def test_parses_failed_login(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text("2026-04-01 10:00:01 LOGIN FAILED user=admin ip=192.168.1.10\n")
        logs = parse_log(str(log_file))
        assert len(logs) == 1
        assert logs[0]["ip"] == "192.168.1.10"
        assert logs[0]["status"] == "FAILED"
        assert logs[0]["user"] == "admin"

    def test_skips_empty_lines(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text("2026-04-01 10:00:01 LOGIN FAILED user=admin ip=1.2.3.4\n\n\n")
        logs = parse_log(str(log_file))
        assert len(logs) == 1

    def test_skips_malformed_lines(self, tmp_path):
        log_file = tmp_path / "test.log"
        log_file.write_text("this is garbage\n2026-04-01 10:00:01 LOGIN FAILED user=admin ip=1.2.3.4\n")
        logs = parse_log(str(log_file))
        assert len(logs) == 1

# pipeline
class TestRunPipeline:
    """Integration test: full pipeline from log file to enriched alert list."""

    def test_pipeline_returns_alerts(self, tmp_path):
        # Write a minimal log file that will trigger brute-force detection
        log_file = tmp_path / "logs.txt"
        log_file.write_text("2026-04-01 10:00:01 LOGIN FAILED user=admin ip=185.220.101.1\n"
                            "2026-04-01 10:00:02 LOGIN FAILED user=admin ip=185.220.101.1\n"
                            "2026-04-01 10:00:03 LOGIN FAILED user=admin ip=185.220.101.1\n")

        mock_intel = {"ip": "185.220.101.1", "country": "DE", "org": "SomeISP"}

        with patch("src.main.parse_log") as mock_parse, \
             patch("src.main.get_ip_info", return_value=mock_intel):

            # Feed in pre-parsed logs so no dependency on file path
            mock_parse.return_value = [{"timestamp": datetime(2026, 4, 1, 10, 0, 1), "status": "FAILED", "user": "admin", "ip": "185.220.101.1"},
                                       {"timestamp": datetime(2026, 4, 1, 10, 0, 2), "status": "FAILED", "user": "admin", "ip": "185.220.101.1"},
                                       {"timestamp": datetime(2026, 4, 1, 10, 0, 3), "status": "FAILED", "user": "admin", "ip": "185.220.101.1"}]

            alerts = run_pipeline()

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert["rule_id"] == "bf-001"
        assert alert["severity"] in ("LOW", "MEDIUM", "HIGH")
        assert "risk_score" in alert
        assert "country" in alert

    def test_pipeline_alert_has_expected_keys(self):
        mock_intel = {"ip": "1.2.3.4", "country": "RU", "org": "SomeISP"}
        expected_keys = {"rule_id", "rule", "mitre", "sigma_severity", "ip", "user", "count", "country", "org",
                         "risk_score", "severity"}

        with patch("src.main.parse_log") as mock_parse, \
             patch("src.main.get_ip_info", return_value=mock_intel):

            mock_parse.return_value = [{"timestamp": datetime(2026, 4, 1, 10, 0, 1), "status": "FAILED", "user": "admin", "ip": "1.2.3.4"},
                                       {"timestamp": datetime(2026, 4, 1, 10, 0, 2), "status": "FAILED", "user": "admin", "ip": "1.2.3.4"},
                                       {"timestamp": datetime(2026, 4, 1, 10, 0, 3), "status": "FAILED", "user": "admin", "ip": "1.2.3.4"}]

            alerts = run_pipeline()

        assert len(alerts) >= 1
        for alert in alerts:
            assert expected_keys.issubset(alert.keys()), f"Missing keys: {expected_keys - alert.keys()}"