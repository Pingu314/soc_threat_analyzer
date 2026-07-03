"""
test_dashboard.py - Flask dashboard tests for src/dashboard.py

Covers:
    GET  /               - home endpoint
    GET  /alerts         - cached sample alerts
    GET  /alerts/summary - severity/rule breakdown
    POST /upload         - single and multi-file upload
    DELETE /cache        - cache reset
"""

import io
from unittest.mock import patch

import pytest

import src.dashboard as dashboard_module
from src.dashboard import app

MOCK_ALERTS = [
    {"rule_id": "bf-001", "rule": "Brute Force Detection", "mitre": "T1110.001",
     "sigma_severity": "high", "ip": "185.220.101.1", "user": "multiple",
     "count": 3, "country": "DE", "org": "SomeISP", "risk_score": 9, "severity": "LOW"},
    {"rule_id": "it-001", "rule": "Impossible Travel Detection", "mitre": "T1078",
     "sigma_severity": "medium", "ip": "multiple", "user": "jsmith",
     "count": 2, "country": "Unknown", "org": "Unknown", "risk_score": 10,
     "severity": "MEDIUM", "distinct_ips": "1.1.1.1, 2.2.2.2"},
    {"rule_id": "ps-001", "rule": "Password Spraying Detection", "mitre": "T1110.003",
     "sigma_severity": "high", "ip": "45.83.64.1", "user": "multiple",
     "count": 5, "country": "DE", "org": "SomeISP", "risk_score": 25, "severity": "HIGH"},
]

LOG_CONTENT = (
    "2026-04-01 10:00:01 LOGIN FAILED user=admin ip=185.220.101.1\n"
    "2026-04-01 10:00:02 LOGIN FAILED user=admin ip=185.220.101.1\n"
    "2026-04-01 10:00:03 LOGIN FAILED user=admin ip=185.220.101.1\n"
)


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture(autouse=True)
def reset_cache():
    """Reset the dashboard cache before and after every test."""
    dashboard_module._cached_alerts = None
    yield
    dashboard_module._cached_alerts = None


# ---------------------------------------------------------------------------
# GET /
# ---------------------------------------------------------------------------

class TestHome:
    def test_returns_200(self, client):
        response = client.get("/")
        assert response.status_code == 200

    def test_contains_message(self, client):
        data = client.get("/").get_json()
        assert "message" in data

    def test_contains_endpoints(self, client):
        data = client.get("/").get_json()
        assert "endpoints" in data
        assert "/alerts" in str(data["endpoints"])
        assert "/upload" in str(data["endpoints"])

    def test_contains_upload_params(self, client):
        data = client.get("/").get_json()
        assert "upload_params" in data
        assert "threshold" in data["upload_params"]


# ---------------------------------------------------------------------------
# GET /alerts
# ---------------------------------------------------------------------------

class TestAlerts:
    def test_returns_200(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            response = client.get("/alerts")
        assert response.status_code == 200

    def test_returns_alerts_list(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            data = client.get("/alerts").get_json()
        assert "alerts" in data
        assert isinstance(data["alerts"], list)

    def test_total_alerts_count(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            data = client.get("/alerts").get_json()
        assert data["total_alerts"] == len(MOCK_ALERTS)

    def test_cache_used_on_second_call(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS) as mock_pipeline:
            client.get("/alerts")
            client.get("/alerts")
        assert mock_pipeline.call_count == 1

    def test_empty_pipeline_returns_empty_list(self, client):
        with patch("src.dashboard.run_pipeline", return_value=[]):
            data = client.get("/alerts").get_json()
        assert data["alerts"] == []
        assert data["total_alerts"] == 0


# ---------------------------------------------------------------------------
# GET /alerts/summary
# ---------------------------------------------------------------------------

class TestAlertsSummary:
    def test_returns_200(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            response = client.get("/alerts/summary")
        assert response.status_code == 200

    def test_contains_required_keys(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            data = client.get("/alerts/summary").get_json()
        assert "total_alerts" in data
        assert "by_severity" in data
        assert "by_rule" in data

    def test_severity_counts_correct(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            data = client.get("/alerts/summary").get_json()
        assert data["by_severity"]["HIGH"] == 1
        assert data["by_severity"]["MEDIUM"] == 1
        assert data["by_severity"]["LOW"] == 1

    def test_rule_counts_correct(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            data = client.get("/alerts/summary").get_json()
        assert data["by_rule"]["bf-001"] == 1
        assert data["by_rule"]["it-001"] == 1
        assert data["by_rule"]["ps-001"] == 1

    def test_total_matches_alerts(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            data = client.get("/alerts/summary").get_json()
        assert data["total_alerts"] == len(MOCK_ALERTS)


# ---------------------------------------------------------------------------
# POST /upload
# ---------------------------------------------------------------------------

class TestUpload:
    def _file(self, content: str = LOG_CONTENT, filename: str = "auth.log"):
        return (io.BytesIO(content.encode()), filename)

    def test_single_file_returns_200(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            response = client.post(
                "/upload",
                data={"file": self._file()},
                content_type="multipart/form-data",
            )
        assert response.status_code == 200

    def test_single_file_returns_alerts(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            data = client.post(
                "/upload",
                data={"file": self._file()},
                content_type="multipart/form-data",
            ).get_json()
        assert "alerts" in data
        assert "total_alerts" in data
        assert "files_processed" in data

    def test_no_file_returns_400(self, client):
        response = client.post("/upload", content_type="multipart/form-data")
        assert response.status_code == 400
        assert "error" in response.get_json()

    def test_invalid_extension_returns_400(self, client):
        response = client.post(
            "/upload",
            data={"file": self._file(filename="data.csv")},
            content_type="multipart/form-data",
        )
        assert response.status_code == 400
        assert "Invalid file type" in response.get_json()["error"]

    def test_multiple_files_uses_multi_pipeline(self, client):
        with patch("src.dashboard.run_pipeline_multi",
                   return_value=MOCK_ALERTS) as mock_multi:
            client.post(
                "/upload",
                data={"file": [self._file("data\n", "a.log"),
                                self._file("data\n", "b.log")]},
                content_type="multipart/form-data",
            )
        mock_multi.assert_called_once()

    def test_single_file_uses_single_pipeline(self, client):
        with patch("src.dashboard.run_pipeline",
                   return_value=MOCK_ALERTS) as mock_single:
            client.post(
                "/upload",
                data={"file": self._file()},
                content_type="multipart/form-data",
            )
        mock_single.assert_called_once()

    def test_txt_extension_accepted(self, client):
        with patch("src.dashboard.run_pipeline", return_value=[]):
            response = client.post(
                "/upload",
                data={"file": self._file(filename="auth.txt")},
                content_type="multipart/form-data",
            )
        assert response.status_code == 200

    def test_threshold_param_passed(self, client):
        with patch("src.dashboard.run_pipeline",
                   return_value=[]) as mock_pipeline:
            client.post(
                "/upload?threshold=2",
                data={"file": self._file()},
                content_type="multipart/form-data",
            )
        call_kwargs = mock_pipeline.call_args[1]
        assert call_kwargs.get("threshold") == 2


# ---------------------------------------------------------------------------
# DELETE /cache
# ---------------------------------------------------------------------------

class TestClearCache:
    def test_returns_200(self, client):
        response = client.delete("/cache")
        assert response.status_code == 200

    def test_cache_cleared(self, client):
        with patch("src.dashboard.run_pipeline", return_value=MOCK_ALERTS):
            client.get("/alerts")  # populate cache
        assert dashboard_module._cached_alerts is not None
        client.delete("/cache")
        assert dashboard_module._cached_alerts is None

    def test_after_clear_pipeline_runs_again(self, client):
        with patch("src.dashboard.run_pipeline",
                   return_value=MOCK_ALERTS) as mock_pipeline:
            client.get("/alerts")
            client.delete("/cache")
            client.get("/alerts")
        assert mock_pipeline.call_count == 2

    def test_returns_confirmation_message(self, client):
        data = client.delete("/cache").get_json()
        assert "message" in data


# ---------------------------------------------------------------------------
# GET /ui
# ---------------------------------------------------------------------------

class TestUI:
    def test_returns_200(self, client):
        dashboard_module._cached_alerts = MOCK_ALERTS
        response = client.get("/ui")
        assert response.status_code == 200

    def test_returns_html(self, client):
        dashboard_module._cached_alerts = MOCK_ALERTS
        response = client.get("/ui")
        assert b"<!doctype html>" in response.data
        assert b"SOC Threat Analyzer" in response.data

    def test_contains_all_alerts(self, client):
        dashboard_module._cached_alerts = MOCK_ALERTS
        html = client.get("/ui").data.decode()
        for alert in MOCK_ALERTS:
            assert alert["rule"] in html

    def test_sorted_by_risk_score_descending(self, client):
        dashboard_module._cached_alerts = MOCK_ALERTS
        html = client.get("/ui").data.decode()
        spray = html.index("Password Spraying Detection")
        travel = html.index("Impossible Travel Detection")
        brute = html.index("Brute Force Detection")
        assert spray < travel < brute

    def test_severity_chips_rendered(self, client):
        dashboard_module._cached_alerts = MOCK_ALERTS
        html = client.get("/ui").data.decode()
        assert 'chip HIGH' in html
        assert 'chip MEDIUM' in html
        assert 'chip LOW' in html