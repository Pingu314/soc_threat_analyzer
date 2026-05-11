from datetime import datetime
from unittest.mock import patch

from src.main import run_pipeline


class TestRunPipeline:
    """Integration test: full pipeline from log file to enriched alert list."""

    def test_pipeline_returns_alerts(self, tmp_path):
        mock_intel = {"ip": "185.220.101.1", "country": "DE", "org": "SomeISP"}

        with patch("src.main.parse_log") as mock_parse, \
             patch("src.main.get_ip_info", return_value=mock_intel):

            mock_parse.return_value = [
                {"timestamp": datetime(2026, 4, 1, 10, 0, 1),
                 "status": "FAILED", "user": "admin", "ip": "185.220.101.1"},
                {"timestamp": datetime(2026, 4, 1, 10, 0, 2),
                 "status": "FAILED", "user": "admin", "ip": "185.220.101.1"},
                {"timestamp": datetime(2026, 4, 1, 10, 0, 3),
                 "status": "FAILED", "user": "admin", "ip": "185.220.101.1"},
            ]
            alerts = run_pipeline()

        assert len(alerts) >= 1
        alert = alerts[0]
        assert alert["rule_id"] == "bf-001"
        assert alert["severity"] in ("LOW", "MEDIUM", "HIGH")
        assert "risk_score" in alert
        assert "country" in alert

    def test_pipeline_alert_has_expected_keys(self):
        mock_intel = {"ip": "1.2.3.4", "country": "RU", "org": "SomeISP"}
        expected_keys = {
            "rule_id", "rule", "mitre", "sigma_severity",
            "ip", "user", "count", "country", "org",
            "risk_score", "severity",
        }

        with patch("src.main.parse_log") as mock_parse, \
             patch("src.main.get_ip_info", return_value=mock_intel):

            mock_parse.return_value = [
                {"timestamp": datetime(2026, 4, 1, 10, 0, 1),
                 "status": "FAILED", "user": "admin", "ip": "1.2.3.4"},
                {"timestamp": datetime(2026, 4, 1, 10, 0, 2),
                 "status": "FAILED", "user": "admin", "ip": "1.2.3.4"},
                {"timestamp": datetime(2026, 4, 1, 10, 0, 3),
                 "status": "FAILED", "user": "admin", "ip": "1.2.3.4"},
            ]
            alerts = run_pipeline()

        assert len(alerts) >= 1
        for alert in alerts:
            assert expected_keys.issubset(alert.keys()), \
                f"Missing keys: {expected_keys - alert.keys()}"
