import pytest
import requests

import src.threat_intel as ti
from src.threat_intel import get_ip_info, is_private_ip
from unittest.mock import Mock, patch


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear the in-memory IP cache before and after every test."""
    ti._cache.clear()
    yield
    ti._cache.clear()


# ---------------------------------------------------------------------------
# is_private_ip
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# get_ip_info
# ---------------------------------------------------------------------------

class TestGetIpInfo:
    def _mock_response(self, country: str = "DE", org: str = "AS1234 SomeISP",
                       status_code: int = 200) -> Mock:
        mock = Mock()
        mock.status_code = status_code
        mock.json.return_value = {"country": country, "org": org}
        return mock

    def test_public_ip_returns_data(self):
        with patch("src.threat_intel.requests.get",
                   return_value=self._mock_response("DE", "AS1234 SomeISP")):
            result = get_ip_info("8.8.8.8")
        assert result["ip"] == "8.8.8.8"
        assert result["country"] == "DE"
        assert result["org"] == "AS1234 SomeISP"

    def test_private_ip_no_api_call(self):
        with patch("src.threat_intel.requests.get") as mock_get:
            result = get_ip_info("192.168.1.1")
        mock_get.assert_not_called()
        assert result["country"] == "PRIVATE"
        assert result["org"] == "Internal Network"

    def test_cache_hit_no_second_call(self):
        with patch("src.threat_intel.requests.get",
                   return_value=self._mock_response()) as mock_get:
            get_ip_info("1.1.1.1")
            get_ip_info("1.1.1.1")
        assert mock_get.call_count == 1

    def test_cache_stores_result(self):
        with patch("src.threat_intel.requests.get",
                   return_value=self._mock_response("US", "AS15169 Google")):
            result1 = get_ip_info("8.8.8.8")
            result2 = get_ip_info("8.8.8.8")
        assert result1 == result2
        assert "8.8.8.8" in ti._cache

    def test_timeout_returns_none(self):
        with patch("src.threat_intel.requests.get",
                   side_effect=requests.exceptions.Timeout):
            result = get_ip_info("8.8.8.8")
        assert result is None

    def test_connection_error_returns_none(self):
        with patch("src.threat_intel.requests.get",
                   side_effect=requests.exceptions.ConnectionError):
            result = get_ip_info("8.8.8.8")
        assert result is None

    def test_http_429_returns_none(self):
        with patch("src.threat_intel.requests.get",
                   return_value=self._mock_response(status_code=429)):
            result = get_ip_info("8.8.8.8")
        assert result is None

    def test_missing_fields_handled(self):
        mock = Mock()
        mock.status_code = 200
        mock.json.return_value = {}  # no country or org fields
        with patch("src.threat_intel.requests.get", return_value=mock):
            result = get_ip_info("8.8.8.8")
        assert result["country"] == "Unknown"
        assert result["org"] == "Unknown"

    def test_unexpected_error_returns_none(self):
        with patch("src.threat_intel.requests.get",
                   side_effect=Exception("unexpected")):
            result = get_ip_info("8.8.8.8")
        assert result is None
