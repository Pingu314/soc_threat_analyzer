"""
Additional tests to append to test_pipeline.py

Covers:
    _build_arg_parser()  - all CLI arguments
    __main__ execution   - logs-dir, recursive, no-export paths
"""

import subprocess
import sys
import pytest

from src.main import _build_arg_parser, DEFAULT_OUTPUT_PATH


# ---------------------------------------------------------------------------
# _build_arg_parser
# ---------------------------------------------------------------------------

class TestBuildArgParser:
    def test_defaults(self):
        parser = _build_arg_parser()
        args = parser.parse_args([])
        assert args.logs is None
        assert args.logs_dir is None
        assert args.recursive is False
        assert args.output == DEFAULT_OUTPUT_PATH
        assert args.no_export is False
        assert args.threshold is None
        assert args.window is None
        assert args.spray_threshold is None
        assert args.spray_window is None
        assert args.travel_threshold is None
        assert args.travel_window is None

    def test_logs_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--logs", "/path/to/auth.log"])
        assert args.logs == "/path/to/auth.log"

    def test_logs_dir_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--logs-dir", "/path/to/logs/"])
        assert args.logs_dir == "/path/to/logs/"

    def test_recursive_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--logs-dir", "/path/", "--recursive"])
        assert args.recursive is True

    def test_no_export_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--no-export"])
        assert args.no_export is True

    def test_threshold_flags(self):
        parser = _build_arg_parser()
        args = parser.parse_args([
            "--threshold", "2",
            "--window", "3",
            "--spray-threshold", "4",
            "--spray-window", "5",
            "--travel-threshold", "2",
            "--travel-window", "3",
        ])
        assert args.threshold == 2
        assert args.window == 3
        assert args.spray_threshold == 4
        assert args.spray_window == 5
        assert args.travel_threshold == 2
        assert args.travel_window == 3

    def test_output_flag(self):
        parser = _build_arg_parser()
        args = parser.parse_args(["--output", "/custom/path.csv"])
        assert args.output == "/custom/path.csv"

    def test_logs_and_logs_dir_mutually_exclusive(self):
        parser = _build_arg_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--logs", "a.log", "--logs-dir", "/path/"])


# ---------------------------------------------------------------------------
# __main__ execution paths via subprocess
# ---------------------------------------------------------------------------

class TestMainExecution:
    def test_default_run(self, tmp_path):
        """Running with default sample data produces output."""
        result = subprocess.run(
            [sys.executable, "-m", "src.main", "--no-export"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0

    def test_custom_log_file(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "2026-04-01 10:00:01 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:02 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:03 LOGIN FAILED user=admin ip=185.220.101.1\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "src.main",
             "--logs", str(log_file), "--no-export"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0

    def test_logs_dir(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "2026-04-01 10:00:01 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:02 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:03 LOGIN FAILED user=admin ip=185.220.101.1\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "src.main",
             "--logs-dir", str(tmp_path), "--no-export"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0

    def test_logs_dir_recursive(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "auth.log").write_text(
            "2026-04-01 10:00:01 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:02 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:03 LOGIN FAILED user=admin ip=185.220.101.1\n"
        )
        result = subprocess.run(
            [sys.executable, "-m", "src.main",
             "--logs-dir", str(tmp_path), "--recursive", "--no-export"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0

    def test_empty_logs_dir_exits_1(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-m", "src.main", "--logs-dir", str(tmp_path)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 1

    def test_csv_export_creates_file(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text(
            "2026-04-01 10:00:01 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:02 LOGIN FAILED user=admin ip=185.220.101.1\n"
            "2026-04-01 10:00:03 LOGIN FAILED user=admin ip=185.220.101.1\n"
        )
        out = tmp_path / "results.csv"
        result = subprocess.run(
            [sys.executable, "-m", "src.main",
             "--logs", str(log_file), "--output", str(out)],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert out.exists()
