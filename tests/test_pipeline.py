"""
test_pipeline.py - Integration tests for src/main.py

Covers:
    run_pipeline()              - single file, default and custom path, threshold overrides
    run_pipeline_multi()        - multiple files, cross-file correlation
    collect_log_files()         - flat directory scan
    collect_log_files_recursive() - recursive directory scan
    _save_csv()                 - CSV export
"""

import csv
import pathlib
from datetime import datetime
from unittest.mock import patch

from src.main import (
    _save_csv,
    collect_log_files,
    collect_log_files_recursive,
    run_pipeline,
    run_pipeline_multi,
)

# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

SAMPLE_LOGS = [
    {"timestamp": datetime(2026, 4, 1, 10, 0, 1),
     "status": "FAILED", "user": "admin", "ip": "185.220.101.1"},
    {"timestamp": datetime(2026, 4, 1, 10, 0, 2),
     "status": "FAILED", "user": "admin", "ip": "185.220.101.1"},
    {"timestamp": datetime(2026, 4, 1, 10, 0, 3),
     "status": "FAILED", "user": "admin", "ip": "185.220.101.1"},
]

MOCK_INTEL = {"ip": "185.220.101.1", "country": "DE", "org": "SomeISP"}
MOCK_INTEL_RU = {"ip": "1.2.3.4", "country": "RU", "org": "SomeISP"}

EXPECTED_KEYS = {
    "rule_id", "rule", "mitre", "sigma_severity",
    "ip", "user", "count", "country", "org",
    "risk_score", "severity",
}


# ---------------------------------------------------------------------------
# run_pipeline - single file
# ---------------------------------------------------------------------------

class TestRunPipeline:
    def test_returns_alerts(self):
        with patch("src.main.parse_log", return_value=SAMPLE_LOGS), \
             patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline()
        assert len(alerts) >= 1
        assert alerts[0]["rule_id"] == "bf-001"

    def test_alert_has_expected_keys(self):
        with patch("src.main.parse_log", return_value=SAMPLE_LOGS), \
             patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline()
        for alert in alerts:
            assert EXPECTED_KEYS.issubset(alert.keys()), \
                f"Missing keys: {EXPECTED_KEYS - alert.keys()}"

    def test_severity_valid_values(self):
        with patch("src.main.parse_log", return_value=SAMPLE_LOGS), \
             patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline()
        for alert in alerts:
            assert alert["severity"] in ("LOW", "MEDIUM", "HIGH")

    def test_custom_log_path(self, tmp_path):
        log_file = tmp_path / "custom.log"
        log_file.write_text(
            "2026-04-01 10:00:01 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:02 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:03 LOGIN FAILED user=admin ip=185.220.101.1\n"
        )
        with patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline(log_path=log_file)
        assert len(alerts) >= 1

    def test_threshold_override_lower(self):
        with patch("src.main.parse_log", return_value=SAMPLE_LOGS), \
             patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline(threshold=2)
        assert len(alerts) >= 1

    def test_threshold_override_higher_no_alerts(self):
        with patch("src.main.parse_log", return_value=SAMPLE_LOGS), \
             patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline(threshold=100)
        assert alerts == []

    def test_empty_log_returns_empty(self):
        with patch("src.main.parse_log", return_value=[]), \
             patch("src.main.get_ip_info", return_value=None):
            alerts = run_pipeline()
        assert alerts == []

    def test_suspicious_country_increases_risk(self):
        with patch("src.main.parse_log", return_value=SAMPLE_LOGS), \
             patch("src.main.get_ip_info", return_value=MOCK_INTEL_RU):
            alerts = run_pipeline()
        assert alerts[0]["risk_score"] > 9  # base=9, RU adds +5


# ---------------------------------------------------------------------------
# run_pipeline_multi - multiple files with cross-file correlation
# ---------------------------------------------------------------------------

class TestRunPipelineMulti:
    def _write_log(self, path: pathlib.Path, ip: str,
                   user: str = "admin", count: int = 3,
                   status: str = "FAILED") -> pathlib.Path:
        lines = "\n".join(
            f"2026-04-01 10:00:0{i} LOGIN {status} user={user} ip={ip}"
            for i in range(count)
        )
        path.write_text(lines + "\n")
        return path

    def test_single_file_list(self, tmp_path):
        f = self._write_log(tmp_path / "a.log", "185.220.101.1")
        with patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline_multi([f])
        assert len(alerts) >= 1

    def test_two_files_merged(self, tmp_path):
        """Entries from both files combined should trigger brute-force."""
        f1 = self._write_log(tmp_path / "host1.log", "185.220.101.1", count=2)
        f2 = self._write_log(tmp_path / "host2.log", "185.220.101.1", count=2)
        with patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline_multi([f1, f2], threshold=3)
        assert len(alerts) >= 1

    def test_cross_file_impossible_travel(self, tmp_path):
        """Same user logging in from different IPs across two files."""
        f1 = tmp_path / "host1.log"
        f1.write_text("2026-04-01 10:00:00 LOGIN SUCCESS user=jsmith ip=185.220.101.1\n")
        f2 = tmp_path / "host2.log"
        f2.write_text("2026-04-01 10:01:00 LOGIN SUCCESS user=jsmith ip=103.21.244.0\n")
        with patch("src.main.get_ip_info", return_value=None):
            alerts = run_pipeline_multi([f1, f2])
        rule_ids = {a["rule_id"] for a in alerts}
        assert "it-001" in rule_ids

    def test_empty_list_returns_empty(self):
        alerts = run_pipeline_multi([])
        assert alerts == []

    def test_threshold_override(self, tmp_path):
        f = self._write_log(tmp_path / "a.log", "185.220.101.1", count=2)
        with patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline_multi([f], threshold=2)
        assert len(alerts) >= 1

    def test_alert_keys_present(self, tmp_path):
        f = self._write_log(tmp_path / "a.log", "185.220.101.1")
        with patch("src.main.get_ip_info", return_value=MOCK_INTEL):
            alerts = run_pipeline_multi([f])
        for alert in alerts:
            assert EXPECTED_KEYS.issubset(alert.keys())


# ---------------------------------------------------------------------------
# collect_log_files
# ---------------------------------------------------------------------------

class TestCollectLogFiles:
    def test_single_log_file(self, tmp_path):
        f = tmp_path / "auth.log"
        f.write_text("data")
        assert collect_log_files(f) == [f]

    def test_single_txt_file(self, tmp_path):
        f = tmp_path / "auth.txt"
        f.write_text("data")
        assert collect_log_files(f) == [f]

    def test_unsupported_extension_skipped(self, tmp_path):
        f = tmp_path / "auth.csv"
        f.write_text("data")
        assert collect_log_files(f) == []

    def test_directory_finds_log_and_txt(self, tmp_path):
        (tmp_path / "a.log").write_text("data")
        (tmp_path / "b.txt").write_text("data")
        (tmp_path / "c.csv").write_text("data")
        result = collect_log_files(tmp_path)
        assert len(result) == 2
        assert all(f.suffix in {".log", ".txt"} for f in result)

    def test_directory_does_not_recurse(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "top.log").write_text("data")
        (sub / "nested.log").write_text("data")
        result = collect_log_files(tmp_path)
        assert len(result) == 1
        assert result[0].name == "top.log"

    def test_empty_directory(self, tmp_path):
        assert collect_log_files(tmp_path) == []

    def test_nonexistent_path(self, tmp_path):
        assert collect_log_files(tmp_path / "ghost.log") == []


# ---------------------------------------------------------------------------
# collect_log_files_recursive
# ---------------------------------------------------------------------------

class TestCollectLogFilesRecursive:
    def test_finds_nested_files(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (tmp_path / "top.log").write_text("data")
        (sub / "nested.log").write_text("data")
        result = collect_log_files_recursive(tmp_path)
        assert len(result) == 2

    def test_deep_nesting(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / "deep.log").write_text("data")
        (tmp_path / "top.log").write_text("data")
        result = collect_log_files_recursive(tmp_path)
        assert len(result) == 2

    def test_ignores_non_log_extensions(self, tmp_path):
        (tmp_path / "data.csv").write_text("data")
        (tmp_path / "auth.log").write_text("data")
        result = collect_log_files_recursive(tmp_path)
        assert len(result) == 1

    def test_single_file_input(self, tmp_path):
        f = tmp_path / "auth.log"
        f.write_text("data")
        result = collect_log_files_recursive(f)
        assert result == [f]


# ---------------------------------------------------------------------------
# _save_csv
# ---------------------------------------------------------------------------

class TestSaveCsv:
    def test_creates_file(self, tmp_path):
        alerts = [{"rule_id": "bf-001", "rule": "Brute Force", "mitre": "T1110.001",
                   "sigma_severity": "high", "ip": "1.2.3.4", "user": "admin",
                   "count": 3, "country": "DE", "org": "SomeISP",
                   "risk_score": 9, "severity": "LOW"}]
        out = str(tmp_path / "output" / "alerts.csv")
        _save_csv(alerts, out)
        assert pathlib.Path(out).exists()

    def test_csv_has_correct_columns(self, tmp_path):
        alerts = [{"rule_id": "bf-001", "rule": "Brute Force", "mitre": "T1110.001",
                   "sigma_severity": "high", "ip": "1.2.3.4", "user": "admin",
                   "count": 3, "country": "DE", "org": "SomeISP",
                   "risk_score": 9, "severity": "LOW"}]
        out = str(tmp_path / "alerts.csv")
        _save_csv(alerts, out)
        with open(out) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["rule_id"] == "bf-001"
        assert rows[0]["severity"] == "LOW"

    def test_empty_alerts_writes_headers_only(self, tmp_path):
        out = str(tmp_path / "alerts.csv")
        _save_csv([], out)
        with open(out) as f:
            content = f.read()
        assert "rule_id" in content
        assert len(content.strip().split("\n")) == 1  # header only
