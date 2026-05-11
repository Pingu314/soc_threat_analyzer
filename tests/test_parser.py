from src.parser import parse_log


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
        log_file.write_text(
            "this is garbage\n"
            "2026-04-01 10:00:01 LOGIN FAILED user=admin ip=1.2.3.4\n"
        )
        logs = parse_log(str(log_file))
        assert len(logs) == 1
