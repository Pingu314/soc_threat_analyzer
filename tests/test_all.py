from datetime import datetime, timedelta

from src.risk_scoring import calculate_risk, get_severity, map_mitre
from src.detector import detect_bruteforce
from src.parser import parse_log
from src.threat_intel import is_private_ip

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
        alert = {"ip": "1.2.3.4", "count": 3}
        assert calculate_risk(alert, None) == 9

    def test_suspicious_country(self):
        alert = {"ip": "1.2.3.4", "count": 3}
        intel = {"ip": "1.2.3.4", "country": "RU", "org": "SomeISP"}
        assert calculate_risk(alert, intel) == 14

    def test_tor_node(self):
        alert = {"ip": "1.2.3.4", "count": 3}
        intel = {"ip": "1.2.3.4", "country": "DE", "org": "Tor Network"}
        assert calculate_risk(alert, intel) == 14

    def test_no_intel(self):
        alert = {"ip": "1.2.3.4", "count": 2}
        assert calculate_risk(alert, None) == 6

class TestMapMitre:
    def test_known_rule(self):
        assert map_mitre("Brute Force Detection") == "T1110"

    def test_unknown_rule(self):
        assert map_mitre("Some Unknown Rule") == "UNKNOWN"

    def test_none(self):
        assert map_mitre(None) == "UNKNOWN"

class TestDetectBruteforce:
    @staticmethod
    def _make_logs(ip, count, minutes_apart=0.1):
        base = datetime(2026, 1, 1, 10, 0, 0)
        return [{"ip": ip,
                 "status": "FAILED",
                 "timestamp": base + timedelta(minutes=i * minutes_apart)}
                for i in range(count)]

    def test_triggers_at_threshold(self):
        logs = self._make_logs("1.2.3.4", 3)
        alerts = detect_bruteforce(logs, threshold=3, window_minutes=5)
        assert len(alerts) == 1
        assert alerts[0]["ip"] == "1.2.3.4"

    def test_no_alert_below_threshold(self):
        logs = self._make_logs("1.2.3.4", 2)
        alerts = detect_bruteforce(logs, threshold=3, window_minutes=5)
        assert len(alerts) == 0

    def test_outside_time_window(self):
        logs = self._make_logs("1.2.3.4", 3, minutes_apart=10)
        alerts = detect_bruteforce(logs, threshold=3, window_minutes=5)
        assert len(alerts) == 0

    def test_success_not_counted(self):
        base = datetime(2026, 1, 1, 10, 0, 0)
        logs = [{"ip": "1.2.3.4", "status": "FAILED", "timestamp": base},
                {"ip": "1.2.3.4", "status": "SUCCESS", "timestamp": base + timedelta(seconds=10)},
                {"ip": "1.2.3.4", "status": "FAILED", "timestamp": base + timedelta(seconds=20)},]
        alerts = detect_bruteforce(logs, threshold=3, window_minutes=5)
        assert len(alerts) == 0

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